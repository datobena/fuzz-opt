/*
 * mutation_dump_afl.c -- AFL++ custom-mutator shim for phase-2 mutation capture.
 *
 * Replaces mutation_dump_mutator.c (libFuzzer). That one had to be LINKED INTO
 * the target, because LLVMFuzzerCustomMutator is a static weak symbol that cannot
 * be LD_PRELOADed -- requiring a diagnostic rebuild with an object injected onto
 * build.sh's link line. AFL++ loads custom mutators at RUNTIME via
 * AFL_CUSTOM_MUTATOR_LIBRARY, so the target is never rebuilt or relinked. That is
 * what lets a LIVE phase-3 trial carry this shim.
 *
 * Why post_process and not fuzz:
 *   afl_custom_fuzz REPLACES AFL's mutators, changing the mutation distribution
 *   -- the captured corpus would stop reflecting the workload phase 3 runs.
 *   afl_custom_post_process is a pass-through called on EVERY input just before
 *   execution, so the distribution is untouched, and it also sees inputs AFL
 *   later discards. The profile must reflect what the fuzzer EXECUTES, not what
 *   it keeps.
 *
 * Lifecycle (collect -> dump -> idle -> re-arm):
 *   Mutations accumulate IN MEMORY. On reaching the cap the whole batch is
 *   written out once and the shim goes IDLE -- no per-exec work at all for the
 *   rest of the period. The orchestrator re-arms it for the next optimization
 *   round by removing the completion marker, which the shim notices on a cheap
 *   periodic check.
 *
 *   Buffering in memory rather than writing a file per mutation is what makes
 *   this affordable inside a measured trial: 20k small file creations spread
 *   through a campaign is real I/O, one batched dump is not.
 *
 * Env:
 *   MUTATION_DUMP_DIR        output directory (unset -> capture disabled)
 *   MUTATION_DUMP_CAP        mutations per batch (default 20000)
 *   MUTATION_DUMP_MODE       reservoir (default) | prefix
 *   MUTATION_DUMP_MAX_BYTES  memory ceiling for the batch (default 512 MiB)
 *   MUTATION_DUMP_EVERY      pre-filter: consider 1 of every N (default 1)
 *   MUTATION_DUMP_SEED       PRNG seed, so a capture is reproducible
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MODE_RESERVOIR 0
#define MODE_PREFIX 1

/* How often, in calls, an idle shim checks whether it has been re-armed. Cheap
 * enough to vanish into noise, frequent enough to catch a round boundary. */
#define REARM_CHECK_INTERVAL 4096

typedef struct {
    uint8_t *data;
    size_t   len;
} entry_t;

typedef struct {
    const char   *dir;
    char          marker[4096];
    unsigned long cap;
    unsigned long every;
    int           mode;
    size_t        max_bytes;

    entry_t      *slots;
    unsigned long filled;     /* slots in use */
    size_t        bytes;      /* bytes held */

    unsigned long produced;   /* every call */
    unsigned long candidates; /* post-`every` filter */
    unsigned long batches;
    int           idle;       /* dumped; waiting to be re-armed */
    unsigned long since_check;

    uint64_t      rng;
    int           pid;
} dump_state_t;

static uint64_t mdump_next(dump_state_t *st) {
    uint64_t z = (st->rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static unsigned long env_ul(const char *name, unsigned long dflt) {
    const char *v = getenv(name);
    if (!v || !*v) return dflt;
    char *end = NULL;
    unsigned long parsed = strtoul(v, &end, 10);
    return (end && *end == '\0' && parsed > 0) ? parsed : dflt;
}

static void slot_set(dump_state_t *st, unsigned long i,
                     const uint8_t *buf, size_t len) {
    entry_t *e = &st->slots[i];
    uint8_t *copy = (uint8_t *)malloc(len ? len : 1);
    if (!copy) return;
    if (len) memcpy(copy, buf, len);
    if (e->data) {
        st->bytes -= e->len;
        free(e->data);
    }
    e->data = copy;
    e->len = len;
    st->bytes += len;
}

/* Write the batch out, then go idle. */
static void mdump_flush(dump_state_t *st) {
    char path[4096];
    unsigned long written = 0;
    for (unsigned long i = 0; i < st->filled; i++) {
        if (!st->slots[i].data) continue;
        snprintf(path, sizeof(path), "%s/mut_%d_%08lu", st->dir, st->pid, i);
        FILE *f = fopen(path, "wb");
        if (!f) continue;
        if (st->slots[i].len) fwrite(st->slots[i].data, 1, st->slots[i].len, f);
        fclose(f);
        written++;
        free(st->slots[i].data);
        st->slots[i].data = NULL;
        st->slots[i].len = 0;
    }
    fprintf(stderr, "[mutation_dump_afl] batch %lu: wrote %lu mutations "
                    "(produced=%lu candidates=%lu)\n",
            st->batches, written, st->produced, st->candidates);

    /* Marker last: its presence means the batch is complete, so a reader never
     * consumes a half-written set. Removing it is what re-arms the shim. */
    FILE *m = fopen(st->marker, "w");
    if (m) { fprintf(m, "%lu\n", written); fclose(m); }

    st->filled = 0;
    st->bytes = 0;
    st->candidates = 0;
    st->batches++;
    st->idle = 1;
}

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    dump_state_t *st = (dump_state_t *)calloc(1, sizeof(dump_state_t));
    if (!st) return NULL;
    st->dir       = getenv("MUTATION_DUMP_DIR");
    st->cap       = env_ul("MUTATION_DUMP_CAP", 20000);
    st->every     = env_ul("MUTATION_DUMP_EVERY", 1);
    st->max_bytes = (size_t)env_ul("MUTATION_DUMP_MAX_BYTES", 512UL * 1024 * 1024);
    st->rng       = (uint64_t)env_ul("MUTATION_DUMP_SEED", seed ? seed : 0x243F6A88ULL);
    st->pid       = (int)getpid();

    const char *mode = getenv("MUTATION_DUMP_MODE");
    st->mode = (mode && strcmp(mode, "prefix") == 0) ? MODE_PREFIX : MODE_RESERVOIR;

    if (st->dir) {
        snprintf(st->marker, sizeof(st->marker), "%s/.batch_complete", st->dir);
        st->slots = (entry_t *)calloc(st->cap, sizeof(entry_t));
        if (!st->slots) st->dir = NULL;
    }
    fprintf(stderr, "[mutation_dump_afl] dir=%s cap=%lu mode=%s max_bytes=%zu\n",
            st->dir ? st->dir : "(unset -> disabled)", st->cap,
            st->mode == MODE_PREFIX ? "prefix" : "reservoir", st->max_bytes);
    return st;
}

size_t afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size,
                               uint8_t **out_buf) {
    dump_state_t *st = (dump_state_t *)data;
    *out_buf = buf;
    if (!st || !st->dir) return buf_size;

    if (st->idle) {
        /* Dormant between rounds: one counter and a stat() every few thousand
         * calls, so an idle shim costs effectively nothing. */
        if (++st->since_check < REARM_CHECK_INTERVAL) return buf_size;
        st->since_check = 0;
        struct stat sb;
        if (stat(st->marker, &sb) != 0) {
            st->idle = 0;
            fprintf(stderr, "[mutation_dump_afl] re-armed for batch %lu\n", st->batches);
        }
        return buf_size;
    }

    st->produced++;
    if (st->every > 1 && (st->produced % st->every) != 0) return buf_size;

    unsigned long t = ++st->candidates;
    if (st->filled < st->cap) {
        slot_set(st, st->filled, buf, buf_size);
        st->filled++;
    } else if (st->mode == MODE_RESERVOIR) {
        /* Algorithm R: keep with probability cap/t, so the batch is a uniform
         * sample over the whole collection window rather than its opening. */
        uint64_t r = mdump_next(st) % t;
        if (r < st->cap) slot_set(st, (unsigned long)r, buf, buf_size);
    }

    /* Memory ceiling: a target with large inputs could otherwise hold gigabytes
     * inside a live trial. Dumping early is better than being OOM-killed. */
    if (st->filled >= st->cap || st->bytes >= st->max_bytes) mdump_flush(st);
    return buf_size;
}

void afl_custom_deinit(void *data) {
    dump_state_t *st = (dump_state_t *)data;
    if (!st) return;
    /* Partial batch on shutdown is still useful; the marker tells readers it is
     * complete-as-of-now rather than in flight. */
    if (st->dir && st->filled) mdump_flush(st);
    fprintf(stderr, "[mutation_dump_afl] done: produced=%lu batches=%lu\n",
            st->produced, st->batches);
    free(st->slots);
    free(st);
}
