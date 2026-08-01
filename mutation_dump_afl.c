/*
 * mutation_dump_afl.c -- AFL++ custom-mutator shim for phase-2 mutation capture.
 *
 * Replaces mutation_dump_mutator.c, the libFuzzer version. That one had to be
 * LINKED INTO the target (LLVMFuzzerCustomMutator is a static weak symbol that
 * cannot be LD_PRELOADed), which meant a whole diagnostic rebuild with an object
 * injected onto the link line in build.sh.
 *
 * AFL++ loads custom mutators at RUNTIME via AFL_CUSTOM_MUTATOR_LIBRARY, so this
 * is a plain .so and the target is never rebuilt or relinked.
 *
 * Why post_process and not fuzz:
 *   afl_custom_fuzz REPLACES AFL's mutators, changing the mutation distribution
 *   -- the captured corpus would no longer reflect the workload phase 3 runs.
 *   afl_custom_post_process is called on EVERY input just before execution and
 *   is a pass-through here, so the distribution is untouched. It also sees inputs
 *   AFL discards, which is the point: the profile must reflect what the fuzzer
 *   EXECUTES, not just what it keeps.
 *
 * Sampling mirrors the libFuzzer shim (Vitter's Algorithm R): fill the reservoir
 * with the first CAP mutations, then keep the t-th with probability CAP/t,
 * evicting a uniformly chosen slot. The result is a uniform sample over the WHOLE
 * run rather than its opening prefix, which matters because early mutations are
 * shallow-queue and unrepresentative.
 *
 * Env:
 *   MUTATION_DUMP_DIR    directory to write into (required; no dir = no capture)
 *   MUTATION_DUMP_CAP    reservoir size / file cap (default 20000)
 *   MUTATION_DUMP_EVERY  pre-filter: consider 1 of every N produced (default 1)
 *   MUTATION_DUMP_SEED   PRNG seed, so a capture is reproducible
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    const char   *dir;
    unsigned long cap;
    unsigned long every;
    unsigned long produced;   /* every call */
    unsigned long candidates; /* post-`every` filter */
    uint64_t      rng;
    int           pid;
} dump_state_t;

/* splitmix64: small, well-distributed, deterministic from the seed. */
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

static void mdump_write(dump_state_t *st, unsigned long slot,
                        const uint8_t *buf, size_t len) {
    char path[4096];
    /* pid in the name keeps slots unique if AFL ever forks the mutator; the
     * slot index means a reservoir replacement overwrites in place. */
    snprintf(path, sizeof(path), "%s/mut_%d_%08lu", st->dir, st->pid, slot);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    if (len) fwrite(buf, 1, len, f);
    fclose(f);
}

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    dump_state_t *st = (dump_state_t *)calloc(1, sizeof(dump_state_t));
    if (!st) return NULL;
    st->dir   = getenv("MUTATION_DUMP_DIR");
    st->cap   = env_ul("MUTATION_DUMP_CAP", 20000);
    st->every = env_ul("MUTATION_DUMP_EVERY", 1);
    st->rng   = (uint64_t)env_ul("MUTATION_DUMP_SEED", seed ? seed : 0x243F6A88ULL);
    st->pid   = (int)getpid();
    fprintf(stderr, "[mutation_dump_afl] dir=%s cap=%lu every=%lu\n",
            st->dir ? st->dir : "(unset -> capture disabled)", st->cap, st->every);
    return st;
}

/* Pass-through: returns the buffer unchanged, so AFL executes exactly what it
 * would have without this shim loaded. */
size_t afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size,
                               uint8_t **out_buf) {
    dump_state_t *st = (dump_state_t *)data;
    *out_buf = buf;
    if (!st || !st->dir) return buf_size;

    st->produced++;
    if (st->every > 1 && (st->produced % st->every) != 0) return buf_size;

    unsigned long t = ++st->candidates;
    if (t <= st->cap) {
        mdump_write(st, t - 1, buf, buf_size);
    } else {
        /* Algorithm R: keep with probability cap/t. */
        uint64_t r = mdump_next(st) % t;
        if (r < st->cap) mdump_write(st, (unsigned long)r, buf, buf_size);
    }
    return buf_size;
}

void afl_custom_deinit(void *data) {
    dump_state_t *st = (dump_state_t *)data;
    if (st) {
        fprintf(stderr, "[mutation_dump_afl] produced=%lu candidates=%lu\n",
                st->produced, st->candidates);
        free(st);
    }
}
