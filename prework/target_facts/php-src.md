- Build flags: the fuzz build compiles at `-O3` with AddressSanitizer, and there is **no LTO**.
  Cross-translation-unit inlining therefore never happens — an `inline`/`always_inline` hint only
  takes effect within the same `.c` file, not across files.
- `ZEND_DEBUG` is **1** here (the build passes `--enable-debug-assertions`). Under `ZEND_DEBUG` the
  macros `zend_never_inline` and `zend_always_inline` expand to **nothing**. To force a function to
  stay out of line (or to be inlined) you must spell the attribute directly —
  `__attribute__((noinline))` / `__attribute__((always_inline))` — the `zend_*` macros will silently
  do nothing.
- The lexer and parser are **generated**, not hand-written: `Zend/zend_language_scanner.c` is
  produced by re2c from `Zend/zend_language_scanner.l`, and `Zend/zend_language_parser.c` by bison
  from `Zend/zend_language_parser.y`. You may edit either the generated `.c` or its `.l`/`.y` source;
  the harness preserves whichever file you actually edit, so a fold placed in the generated `.c`
  survives the rebuild.
- opcache is enabled (`--enable-opcache`). The engine already interns strings, so adding your own
  interned-string pool or string-table fold is a **no-op** on this target — don't spend a cycle on it.
- About 60–70% of every profile is code you **cannot** fold: the ASan runtime, the `afl-showmap`
  forkserver, the kernel, and libc. Do not try to fold sanitizer or harness/forkserver frames. The
  largest *foldable* cost is the per-call ASan **fake-stack frame** on hot functions (e.g.
  `lex_scan`): if a function has an address-taken local used only on a cold/error path, moving that
  local into a separate `noinline` helper removes the hot function's per-call fake-stack frame
  (the `__asan_stack_malloc` + shadow poisoning) while preserving stack-use-after-return detection.
- The per-`malloc` ASan heap cost is **not** foldable: pooling small allocations to dodge it would
  suppress heap-overflow/use-after-free detection, which is an automatic reject.
