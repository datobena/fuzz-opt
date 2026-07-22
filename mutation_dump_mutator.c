/*
 * mutation_dump_mutator.c -- libFuzzer custom-mutator shim for the mutation
 * capture used by run_hotspotdiff.py and phase-2 (mutation_capture.py).
 *
 * Linked into a DIAGNOSTIC build of a fuzz target (as an object on the link
 * line, before $LIB_FUZZING_ENGINE) so libFuzzer calls this for every mutation
 * instead of its built-in mutator. We delegate to the built-in LLVMFuzzerMutate
 * so the mutation DISTRIBUTION is unchanged, and persist a bounded sample of the
 * produced inputs to $MUTATION_DUMP_DIR -- regardless of whether they later
 * increase coverage. The saved corpus is exactly what a later `-runs=0` replay
 * profiles, so profile == replay == corpus.
 *
 * Sampling (MUTATION_DUMP_RESERVOIR):
 *   1 (reservoir, uniform)  Fill the reservoir with the first CAP mutations,
 *       then for the t-th candidate (t>CAP) keep it with probability CAP/t,
 *       evicting a uniformly-chosen slot -- Vitter's Algorithm R. Result is a
 *       UNIFORM random sample over the WHOLE stream (does not stop early, so it
 *       reaches the deep/late-queue mutations, not just the opening prefix).
 *   0 (prefix, legacy)      Save the first CAP mutations in order, then _exit(0).
 *       Fast but biased toward the early (shallow-queue) part of the run.
 *
 * Env:
 *   MUTATION_DUMP_DIR        directory to write mutations into (required to save)
 *   MUTATION_DUMP_CAP        reservoir size / max files (default 50000)
 *   MUTATION_DUMP_EVERY      pre-filter: consider 1 of every N produced (default 1)
 *   MUTATION_DUMP_RESERVOIR  1=reservoir-sample whole stream, 0=first-N prefix (default 0)
 *   MUTATION_DUMP_SEED       PRNG seed for reservoir decisions (default fixed => reproducible)
 *
 * Filenames embed the pid + a fixed slot index so they stay unique under -fork
 * and so a reservoir replacement overwrites its slot in place.
 */
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Provided by the fuzzing engine (libFuzzer) at link time. */
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

static const char *g_dir = NULL;
static unsigned long g_cap = 50000;     /* reservoir size / file cap */
static unsigned long g_every = 1;       /* pre-filter: 1 of every N produced */
static int g_reservoir = 0;             /* 1 = uniform whole-stream sample */
static unsigned long g_produced = 0;    /* mutations produced (all calls) */
static unsigned long g_cand = 0;        /* candidates considered (post-every) */
static uint64_t g_rng = 0x243F6A8885A308D3ULL;
static int g_pid = 0;
static const char *g_qdir = NULL;       /* MUTATION_QUEUE_DIR: guaranteed one-pass over this */
static unsigned long g_qdepth = 5;      /* mutations per queue input (libFuzzer mutate_depth) */
static int g_qdone = 0;                 /* guaranteed queue pass completed */

/* splitmix64: tiny, well-distributed PRNG; deterministic from the seed. */
static uint64_t mdump_next(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Unbiased uniform integer in [0, k) via rejection (no modulo bias). */
static uint64_t mdump_below(uint64_t k) {
    if (k <= 1) return 0;
    uint64_t limit = UINT64_MAX - (UINT64_MAX % k);
    uint64_t x;
    do { x = mdump_next(); } while (x >= limit);
    return x % k;
}

static void mdump_write_slot(unsigned long slot, const uint8_t *Data, size_t n) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/mut_%d_%010lu", g_dir, g_pid, slot);
    FILE *f = fopen(path, "wb");
    if (f) {
        if (n > 0) fwrite(Data, 1, n, f);
        fclose(f);
    }
}

/* Guaranteed one-pass over the initial queue: mutate EVERY seed file once with a
 * mutate_depth-long chain (libFuzzer's per-selection behaviour), writing each to a
 * reserved `g`-prefixed slot that the reservoir never evicts. Ensures every queue
 * input is represented at least once, independent of libFuzzer's weighted
 * selection or the time cap. Called once, on the first mutator call. */
static void mdump_queue_pass(size_t MaxSize) {
    DIR *d = opendir(g_qdir);
    if (!d) return;
    size_t cap = MaxSize ? MaxSize : 1;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { closedir(d); return; }
    struct dirent *ent;
    unsigned long gidx = 0;
    while ((ent = readdir(d)) != NULL) {
        char fpath[8192];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_qdir, ent->d_name);
        FILE *sf = fopen(fpath, "rb");
        if (!sf) continue;
        size_t sz = fread(buf, 1, cap, sf);   /* dirs/". ."/empties read 0 -> skipped */
        fclose(sf);
        if (sz == 0) continue;
        size_t size = sz;
        for (unsigned long k = 0; k < g_qdepth; k++) {
            size = LLVMFuzzerMutate(buf, size, MaxSize);
            char path[4096];
            snprintf(path, sizeof(path), "%s/mut_%d_g%09lu", g_dir, g_pid, gidx++);
            FILE *of = fopen(path, "wb");
            if (of) {
                if (size > 0) fwrite(buf, 1, size, of);
                fclose(of);
            }
        }
    }
    free(buf);
    closedir(d);
}

__attribute__((constructor))
static void mdump_init(void) {
    const char *e;
    g_dir = getenv("MUTATION_DUMP_DIR");
    if ((e = getenv("MUTATION_DUMP_CAP")))       g_cap = strtoul(e, NULL, 10);
    if ((e = getenv("MUTATION_DUMP_EVERY")))     g_every = strtoul(e, NULL, 10);
    if ((e = getenv("MUTATION_DUMP_RESERVOIR"))) g_reservoir = (strtoul(e, NULL, 10) != 0);
    if ((e = getenv("MUTATION_DUMP_SEED"))) {
        uint64_t s = strtoull(e, NULL, 10);
        if (s) g_rng = s;
    }
    g_qdir = getenv("MUTATION_QUEUE_DIR");
    if ((e = getenv("MUTATION_QUEUE_DEPTH"))) g_qdepth = strtoul(e, NULL, 10);
    if (g_qdepth == 0) g_qdepth = 1;
    if (g_every == 0) g_every = 1;
    if (g_cap == 0) g_cap = 1;
    g_pid = (int)getpid();
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize,
                               unsigned int Seed) {
    (void)Seed;
    if (!g_qdone) {                 /* guaranteed queue pass, once, before fuzzing */
        g_qdone = 1;
        if (g_dir && g_qdir) mdump_queue_pass(MaxSize);
    }
    size_t n = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (g_dir && (g_produced % g_every) == 0) {
        unsigned long t = ++g_cand;             /* 1-indexed candidate number */
        if (t <= g_cap) {
            mdump_write_slot(t - 1, Data, n);   /* fill reservoir slot t-1 */
        } else if (g_reservoir) {
            uint64_t j = mdump_below(t);        /* Algorithm R: keep w.p. cap/t */
            if (j < g_cap) mdump_write_slot((unsigned long)j, Data, n);
        }
        if (!g_reservoir && t >= g_cap) {
            /* Prefix mode: cap filled -> stop instead of fuzzing out the rest of
             * the -max_total_time window for mutations we won't save. */
            fprintf(stdout, "MUTATION_DUMP_DONE saved=%lu seen=%lu\n",
                    g_cap, g_produced + 1);
            fflush(stdout);
            _exit(0);
        }
    }
    g_produced++;
    return n;
}
