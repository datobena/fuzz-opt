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
 * Lifecycle (sample continuously -> dump on request -> resume):
 *   Mutations accumulate IN MEMORY across the whole inter-round window. The
 *   orchestrator asks for a batch by creating .dump_now; the shim notices on a
 *   once-a-second check, writes the batch, and resumes sampling immediately.
 *
 *   Sampling must span the WINDOW, not stop when the buffer first fills. At
 *   ~7k exec/s a 20k buffer fills in ~3 seconds, so dumping on full would make
 *   every round profile the first 3 seconds of an hour -- and the 3 seconds
 *   right after a hot-swap, while AFL re-calibrates.
 *
 *   Buffering in memory rather than writing a file per mutation is what makes
 *   this affordable inside a measured trial: 20k small file creations spread
 *   through a campaign is real I/O, one batched dump is not.
 *
 * Env:
 *   MUTATION_DUMP_DIR        output directory (unset -> capture disabled)
 *   MUTATION_DUMP_CAP        mutations per batch (default 30000)
 *   MUTATION_DUMP_MODE       reservoir (default) | prefix
 *   MUTATION_DUMP_MAX_BYTES  memory ceiling for the held sample (default 512 MiB)
 *   MUTATION_DUMP_EVERY      pre-filter: consider 1 of every N (default 1)
 *   MUTATION_DUMP_SEED       PRNG seed, so a capture is reproducible
 *   TRIAL_PAUSE_DIR         opt-in host lease/ack directory (testcase-boundary pause)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MODE_RESERVOIR 0
#define MODE_PREFIX 1

/* How often, in wall-clock ms, the shim checks for a dump request. Time-based,
 * not call-based: a fixed call count (it was 4096) took over a minute to notice
 * a request on a ~60 exec/s target (sanitizer + leak-check builds) and would
 * miss the orchestrator's dump deadline below ~14 exec/s. The clock read is
 * CLOCK_MONOTONIC_COARSE (vDSO, a few ns), negligible next to an execution. */
#define REQUEST_CHECK_MS 1000

typedef struct {
    uint8_t *data;
    size_t   len;
} entry_t;

typedef struct {
    const char   *dir;
    char          marker[4096];
    char          request[4096];
    unsigned long cap;
    unsigned long every;
    int           mode;
    size_t        max_bytes;

    entry_t      *slots;
    unsigned long filled;     /* slots in use */
    size_t        bytes;      /* bytes held */

    unsigned long produced;   /* every call */
    unsigned long candidates; /* post-`every` filter */
    unsigned long over_ceiling; /* picks not stored: would exceed max_bytes */
    unsigned long batches;
    uint64_t      last_check_ms;

    uint64_t      rng;
    int           pid;
    const char   *pause_dir;
    uint64_t      pause_check_ms;
    char          expired_pause[65];
} dump_state_t;

static uint64_t mdump_next(dump_state_t *st) {
    uint64_t z = (st->rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Experimental cooperative pause. post_process runs before AFL starts the
 * next testcase, with no testcase timeout armed. Freezing an arbitrary running
 * container instead lets poll() deadlines expire and manufactures timeouts.
 * Nothing changes unless TRIAL_PAUSE_DIR is supplied by the host. The request
 * is a token and CLOCK_MONOTONIC deadline in ms; an expired lease resumes the
 * fuzzer even if the host controller has died. Never re-ack an expired token.
 */
static int pause_read(const char *path, char token[65], uint64_t *until) {
    unsigned long long value;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int ok = fscanf(f, "%64s %llu", token, &value) == 2;
    fclose(f);
    if (ok) *until = (uint64_t)value;
    return ok;
}

static void pause_before_testcase(dump_state_t *st) {
    if (!st->pause_dir) return;
    uint64_t now = now_ms();
    if (now - st->pause_check_ms < 50) return;
    st->pause_check_ms = now;
    char request[4096], ack[4096], tmp[4096], token[65], current[65];
    uint64_t until;
    if (snprintf(request, sizeof(request), "%s/request", st->pause_dir) >= (int)sizeof(request) ||
        snprintf(ack, sizeof(ack), "%s/ack", st->pause_dir) >= (int)sizeof(ack) ||
        snprintf(tmp, sizeof(tmp), "%s/ack.%d", st->pause_dir, st->pid) >= (int)sizeof(tmp)) return;
    if (!pause_read(request, token, &until) || until <= now ||
        !strcmp(token, st->expired_pause)) return;
    FILE *f = fopen(tmp, "w");
    if (!f) return;  /* No acknowledgement means the host must not proceed. */
    int written = fprintf(f, "%s %d\n", token, st->pid) > 0;
    if (fclose(f) || !written || rename(tmp, ack)) { unlink(tmp); return; }
    for (;;) {
        if (!pause_read(request, current, &until) || strcmp(current, token)) break;
        if (until <= now_ms()) {
            strcpy(st->expired_pause, token);
            break;
        }
        struct timespec delay = {0, 20000000};
        nanosleep(&delay, NULL);
    }
    unlink(ack);
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
                    "(produced=%lu candidates=%lu over_ceiling=%lu)\n",
            st->batches, written, st->produced, st->candidates, st->over_ceiling);

    /* Marker last: its presence means the batch is complete, so a reader never
     * consumes a half-written set. Removing it is what re-arms the shim. */
    FILE *m = fopen(st->marker, "w");
    if (m) { fprintf(m, "%lu\n", written); fclose(m); }

    unlink(st->request);
    st->filled = 0;
    st->bytes = 0;
    st->candidates = 0;
    st->over_ceiling = 0;
    st->batches++;
    /* Resume sampling at once. Going idle here would leave the next window
     * blind for however long the orchestrator takes to harvest. */
}

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    dump_state_t *st = (dump_state_t *)calloc(1, sizeof(dump_state_t));
    if (!st) return NULL;
    st->dir       = getenv("MUTATION_DUMP_DIR");
    st->pause_dir = getenv("TRIAL_PAUSE_DIR");
    st->cap       = env_ul("MUTATION_DUMP_CAP", 30000);
    st->every     = env_ul("MUTATION_DUMP_EVERY", 1);
    st->max_bytes = (size_t)env_ul("MUTATION_DUMP_MAX_BYTES", 512UL * 1024 * 1024);
    st->rng       = (uint64_t)env_ul("MUTATION_DUMP_SEED", seed ? seed : 0x243F6A88ULL);
    st->pid       = (int)getpid();

    const char *mode = getenv("MUTATION_DUMP_MODE");
    st->mode = (mode && strcmp(mode, "prefix") == 0) ? MODE_PREFIX : MODE_RESERVOIR;

    if (st->dir) {
        snprintf(st->marker, sizeof(st->marker), "%s/.batch_complete", st->dir);
        snprintf(st->request, sizeof(st->request), "%s/.dump_now", st->dir);
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
    if (st) pause_before_testcase(st);
    if (!st || !st->dir) return buf_size;

    st->produced++;
    if (st->every > 1 && (st->produced % st->every) != 0) return buf_size;

    /* Memory ceiling: a pick that would push the held sample past max_bytes is
     * not stored (counted in over_ceiling). It used to FLUSH the batch early, and
     * the orchestrator's next request deletes any unrequested batch, so on
     * large-input targets (harfbuzz, woff2: >26 KiB mean over 20k slots) a round
     * kept only the tail of its window -- one review run kept 33% of the
     * executions. Skipping only biases against the largest inputs, and only
     * while the ceiling binds. */
    unsigned long t = ++st->candidates;
    int fits = st->bytes + buf_size <= st->max_bytes;
    if (st->filled < st->cap && fits) {
        slot_set(st, st->filled, buf, buf_size);
        st->filled++;
    } else if (st->mode == MODE_RESERVOIR && st->filled) {
        /* Algorithm R: keep with probability k/t, so the batch is a uniform
         * sample over the whole collection window rather than its opening.
         * k = filled: normally cap, fewer if the ceiling stopped the fill --
         * replacement must still run then, or the batch degrades to a prefix. */
        uint64_t r = mdump_next(st) % t;
        if (r < st->filled) {
            if (st->bytes - st->slots[r].len + buf_size > st->max_bytes)
                st->over_ceiling++;
            else
                slot_set(st, (unsigned long)r, buf, buf_size);
        }
    } else if (!fits) {
        st->over_ceiling++;
    }

    /* Write ONLY on request. Never on `filled >= cap`: flushing the moment the
     * buffer fills would make every mode behave as prefix, since the reservoir
     * branch above is only reached once filled == cap. That bug made each round
     * profile the first ~3 seconds of a 60-minute window -- and the seconds
     * right after a hot-swap, while AFL re-calibrates its queue.
     *
     * In prefix mode the buffer simply stops accepting (the branch above does
     * nothing once full) and the batch is written on request, so both modes
     * dump at the same point and differ only in WHICH mutations they hold. */
    uint64_t now = now_ms();
    if (now - st->last_check_ms >= REQUEST_CHECK_MS) {
        st->last_check_ms = now;
        struct stat sb;
        if (stat(st->request, &sb) == 0) mdump_flush(st);
    }
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
