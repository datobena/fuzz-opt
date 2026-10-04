# LLMs and AI Agents That Optimize Code for Performance (Speed), Outside Security Contexts

Scope note for the report writer: the user's system is "LLM coding agent + runtime profile + measured accept/reject gate on a deterministic replay benchmark, editing C/C++." Every entry below is labeled with **target language** (C/C++ marked as most relevant), **method**, **correctness check**, **benchmark**, and **reported speedup**. Verification status is stated per entry. Where I could only see a search snippet or an abstract (not the full PDF), I say so.

Venue/year verification convention used here:
- **[V]** = verified against a primary source I fetched (arXiv abstract page, publisher page, conference program page, DeepMind blog).
- **[V-listing]** = seen in a primary listing (e.g. icml.cc program page, ICSE/GI program page, GitHub repo of the benchmark authors) but I did not fetch the camera-ready PDF.
- **UNVERIFIED** = appeared only in a search result snippet or aggregator; treat as a lead, not a citation.

---

## Q1. Main benchmarks and datasets: PIE and its successors — what speedups, on what language?

### Takeaway
PIE (ICLR 2024, **C++**) is the foundational dataset and is still the only major benchmark whose primary language is C++; every major 2025–2026 successor (GSO, SWE-Perf, SWE-fficiency, FormulaCode) moved to **repository-level Python** (scientific Python stacks with native backends), so the user's C/C++ setting is comparatively under-served and is a defensible novelty axis. Best PIE-era reported speedup is ~6.9× mean / 9.6× best with best-of-8 sampling; repo-level agentic benchmarks report far harsher numbers (<5% success on GSO).

### Cited Findings

**Foundational (2023–2024)**

- **PIE / "Learning Performance-Improving Code Edits"** — Alexander Shypula, Aman Madaan, Yimeng Zeng, Uri Alon, Jacob Gardner, Milad Hashemi, Graham Neubig, Parthasarathy Ranganathan, Osbert Bastani, Amir Yazdanbakhsh. **ICLR 2024 (Spotlight)** [V, via arXiv abs page]. arXiv:2302.07867. **Language: C++ (MOST RELEVANT).** Dataset: >77,000 competitive-programming C++ submission pairs from IBM CodeNet, with extensive unit tests. Methods: retrieval-based few-shot prompting, chain-of-thought, **performance-conditioned generation**, and **self-play synthetic data augmentation** (i.e. prompting + fine-tuning, no agent loop). Correctness: the dataset's accompanying unit tests. Timing: **gem5 full-system simulator**, explicitly chosen to remove wall-clock measurement variability. Best result: **mean speedup 6.86× with eight generations**, vs. 3.66× average for the human programmers' own optimizations; **best model generation 9.64× vs 9.56× for the fastest human submissions**. — [arXiv:2302.07867](https://arxiv.org/abs/2302.07867)
- PIE artifact/tooling: the authors released `pie-perf` ("Training language models to make programs faster") and a `LearningOpt/pie` repo. — [github.com/madaan/pie-perf](https://github.com/madaan/pie-perf); [github.com/LearningOpt/pie](https://github.com/LearningOpt/pie)
- Secondary description of PIE's construction (approx. 35k editing pairs in the commonly used filtered split, derived from CodeNet; note this conflicts with the paper's 77k figure, which counts the full curated pair set — the 35k figure is the filtered/benchmark split). — [Awesomepapers PIE entry](https://awesomepapers.io/ai-for-code/datasets/performance-improving-code-edits-pie) (aggregator; treat the 77k figure from the paper as authoritative)

**Recent (2025–2026) — repository-level successors**

- **GSO: Challenging Software Optimization Tasks for Evaluating SWE-Agents** — Manish Shetty, Naman Jain, Jinjian Liu, Vijay Kethanaboyina, Koushik Sen, Ion Stoica. arXiv:2505.23671, submitted 29 May 2025 (v3 24 Oct 2025) [V]. The benchmark's own GitHub repo is titled "**[NeurIPS '25]** GSO" [V-listing], but the arXiv abstract page itself lists no venue — cite as NeurIPS 2025 with that caveat. **102 optimization tasks across 10 codebases, "diverse domains and programming languages"** (the abstract does not enumerate them; whether C/C++ is included is **UNVERIFIED** at the abstract level, though the repo set is the kind of Python-with-native-backend stack where C/C++ edits occur). Spec given to the agent: codebase + **a performance test as a precise specification**; success = matching the expert developer's optimization. Result: "**Leading SWE-Agents struggle significantly, achieving less than 5% success rate**, with limited improvements even with inference-time scaling." — [arXiv:2505.23671](https://arxiv.org/abs/2505.23671); [github.com/gso-bench/gso](https://github.com/gso-bench/gso)
- **SWE-Perf: Can Language Models Optimize Code Performance on Real-World Repositories?** — Xinyi He, Qian Liu, Mingzhe Du, Lin Yan, Zhijie Fan, Yiming Huang, Yin Zheng, Zejian Yuan, Zejun Ma. arXiv:2507.12415 (v1 16 Jul 2025; v2 1 Jul 2026); **ICML 2026** [V on arXiv page; ICML poster session listed for Tue 7 Jul 2026, Coex Hall A, V-listing]. **140 instances** from performance-improving GitHub PRs; each instance ships codebase, target functions, performance tests, expert patch, executable environment. Language: not stated in the abstract, but the repos are the standard Python SWE-bench-style set (**UNVERIFIED** — confirm before asserting Python). Agents evaluated: Agentless and OpenHands, file-level and repo-level. Headline finding is qualitative: "a substantial capability gap between existing LLMs and expert-level optimization performance"; no exact gain percentage on the abstract page. — [arXiv:2507.12415](https://arxiv.org/abs/2507.12415); [ICML 2026 poster page](https://icml.cc/virtual/2026/poster/61514)
- **SWE-fficiency: Can Language Models Optimize Real-World Repositories on Real Workloads?** — arXiv:2511.06090 (Nov 2025); **ICML 2026** [V-listing, icml.cc poster page exists]. **Author list UNVERIFIED** (I did not fetch the abstract page). **498 tasks across nine data-science / ML / HPC repositories (numpy, pandas, scipy, …)** — Python-fronted, native-backend. Design is the closest benchmark analogue to the user's gate: it **jointly (i) times a performance workload, (ii) verifies correctness using the repository's own tests, and (iii) keeps correctness and performance workloads separate** — explicitly rejecting earlier benchmarks that used unit-test runtime as a performance proxy. Task curation prunes candidates that introduce new behavior or are unsuitable for reproducible benchmarking. — [arXiv:2511.06090](https://arxiv.org/abs/2511.06090); [ICML 2026 poster page](https://icml.cc/virtual/2026/poster/66745)
- **FormulaCode: Evaluating Agentic Optimization on Large Codebases** — Atharva Sehgal, James Hou, Akanksha Sarkar, Ishaan Mantripragada, Swarat Chaudhuri, Jennifer J. Sun, Yisong Yue. arXiv:2603.16011 (submitted 16 Mar 2026; camera-ready 17 Jul 2026), **ICML** (camera-ready label on the arXiv page; exact ICML year 2026 is the natural reading but the page text says only "ICML Camera Ready" — treat year as **[V-listing]**). **957 performance bottlenecks** drawn from **scientific Python repositories**, with an average of **264.6 community-maintained performance workloads per task** and expert patches. Explicitly multi-objective and fine-grained. Conclusion: "repository-scale, multi-objective optimization remains a major challenge for frontier LLM agents." **Language: Python only; C/C++ not mentioned.** — [arXiv:2603.16011](https://arxiv.org/abs/2603.16011); an OpenReview version exists at [openreview.net/pdf?id=CMdtl83aZF](https://openreview.net/pdf?id=CMdtl83aZF) (blocked by bot check when fetched)
- **ECO: Enhanced Code Optimization via Performance-Aware Prompting for Code-LLMs** — Su-Hyeon Kim, Joonghyuk Hahn, Sooyoung Cha, Yo-Sub Han. arXiv:2510.10517, 12 Oct 2025, cs.PL [V]. Method: prompting — distills *root causes of inefficiency* and the *rationales* behind improvements from slow/fast reference pairs, combining symbolic analysis with retrieval, instead of feeding raw slow-fast pairs. Reported: "**speedups of up to 7.81× while minimizing correctness loss**." Benchmark and language not named on the abstract page (**UNVERIFIED**; the framing strongly implies the PIE setting, i.e. C++, but do not assert it without checking the PDF). — [arXiv:2510.10517](https://arxiv.org/pdf/2510.10517)

**Recent leads seen only in search results (all UNVERIFIED — listed so the writer can chase them)**
- FasterPy: An LLM-based Code Execution Efficiency Optimization Framework — arXiv:2512.22827 (Python, by name).
- PEACE: Towards Efficient Project-Level Efficiency Optimization via Hybrid Code Editing — arXiv:2510.17142.
- EffiBench-X: A Multi-Language Benchmark for Measuring Efficiency of LLM-Generated Code — arXiv:2505.13004 (multi-language; likely the best source for cross-language coverage including C++).
- Rethinking Code Performance Benchmarks for LLMs — arXiv:2607.07619.
- SWE-NFI: Studying and Benchmarking Coding Agents for Non-Functional Improvements — arXiv:2607.27409.
- Evaluating LLMs on Real-World Software Performance Optimization — arXiv:2606.25530.

### Inferences
- The field's center of gravity moved in ~18 months from *function-level, simulator-timed, C++* (PIE) to *repository-level, wall-clock-timed, Python* (GSO/SWE-Perf/SWE-fficiency/FormulaCode). The user's project sits in an unoccupied corner: **repository-level + C/C++ + wall-clock + deterministic replay**.
- SWE-fficiency's three-part design (separate correctness workload, separate performance workload, repo's own tests) is the strongest published justification for the user's "deterministic replay benchmark + accept/reject gate" architecture, and should be cited as precedent.

### Gaps
- I could not confirm whether GSO's 10 codebases include a primarily C/C++ project; the abstract only says "diverse programming languages."
- ECO's benchmark and language are not on the abstract page.
- SWE-fficiency author list not retrieved.

---

## Q2. Agentic and search-based approaches (AlphaEvolve, AlphaDev, FunSearch, evolutionary/LLM hybrids)

### Takeaway
The DeepMind line (FunSearch → AlphaEvolve) established the template the user is implicitly following — **LLM proposes, an automated evaluator scores and gates, keep only what measurably improves** — and AlphaEvolve is the strongest existing evidence that this loop yields real, deployed speedups. AlphaDev is RL-over-assembly, *not* an LLM, and should be cited as a precursor rather than an LLM method.

### Cited Findings

**Recent (2025)**

- **AlphaEvolve: A Gemini-powered coding agent for designing advanced algorithms** — Google DeepMind, announced **May 2025** [V, DeepMind blog]. Method: **evolutionary search over whole codebases**, with an ensemble of LLMs — Gemini Flash for breadth of ideas, Gemini Pro for depth — proposing edits that are then verified by **automated evaluation metrics that run and score each candidate program**, giving "objective, quantifiable assessment." This is exactly the measured-acceptance-gate pattern. **Languages edited: Python (algorithms) and Verilog (hardware circuits)**; it operates on entire codebases rather than isolated functions. Reported results:
  - **0.7% of Google's worldwide compute continuously recovered** via a Borg data-center scheduling heuristic.
  - A **Verilog** change to a TPU matrix-multiply arithmetic circuit (removing unnecessary bits), which passed existing verification and is going into an upcoming TPU.
  - **23% speedup on a critical Gemini architecture kernel → 1% reduction in Gemini's overall training time.**
  - **Up to 32.5% speedup on a FlashAttention kernel** implementation (GPU instruction-level).
  - Mathematically: 4×4 complex matrix multiplication in **48 scalar multiplications**, beating Strassen (1969).
  — [DeepMind blog: AlphaEvolve](https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/); companion white paper PDF at [storage.googleapis.com/.../AlphaEvolve.pdf](https://storage.googleapis.com/deepmind-media/DeepMind.com/Blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/AlphaEvolve.pdf) (fetched but returned unparsed binary; numbers above are from the blog)
- On 50 open mathematics problems AlphaEvolve **matched the best known solution on ~75% and improved it on ~20%**, underperforming on 5%. — [The Register, 15 May 2025](https://www.theregister.com/2025/05/15/google_deepmind_debuts_algorithm_evolving/) (secondary; the same figures appear in the DeepMind materials)
- **GI-Agent: Search-Based LLM Agent for Code Optimization with Genetic Improvement** — Donghyun Lee, William B. Langdon, Justyna Petke (UCL). **GI 2026, the Genetic Improvement workshop co-located with ICSE 2026**, Rio de Janeiro, session Mon 13 Apr 2026 [V, ICSE 2026 program page]. DOI 10.1145/3786162.3793232. Method: LLM-driven mutation/crossover inside a genetic-improvement loop, with **"reflections" (memory of prior compilation and runtime outcomes)** used to condition later generations — i.e. an explicit measured-feedback evolutionary agent. **Benchmarks: SAT4J (Java) and MiniSAT (C++) — C/C++ RELEVANT.** Reported qualitatively: GI-Agent "consistently generates more viable and better variants" when few-shot prompting is combined with structured search; the program page does not give speedup numbers. Preprint: gpbib.cs.ucl.ac.uk/gi2026/lee_2026_GI.pdf. — [ICSE 2026 / GI 2026 program entry](https://conf.researchr.org/details/icse-2026/gi-2026-papers/1/GI-Agent-Search-Based-LLM-Agent-for-Code-Optimization-with-Genetic-Improvement)
- **CodeEvolve: An open source evolutionary coding agent for algorithm discovery and optimization** — arXiv:2510.14150 (v2). Open-source AlphaEvolve-style agent. Details **UNVERIFIED** (search result only). — [arXiv:2510.14150](https://arxiv.org/html/2510.14150v2)

**Foundational (2023)**

- **FunSearch / "Mathematical discoveries from program search with large language models"** — Bernardino Romera-Paredes et al., Google DeepMind. **Nature, December 2023** [V, nature.com]. Method: **evolutionary procedure pairing a frozen pretrained LLM with a systematic evaluator**; searches the space of *programs* (heuristics) rather than solutions. Correctness/quality enforcement: the evaluator "guards against confabulations and incorrect ideas" by scoring every candidate program — no candidate is accepted unscored. Results: new **cap set** constructions beating best-known, and new **online bin-packing** heuristics improving on widely used baselines. Language: Python functions. Not a runtime-speed optimizer per se — it optimizes a scored objective, which in the bin-packing case is solution quality, not wall-clock. — [Nature s41586-023-06924-6](https://www.nature.com/articles/s41586-023-06924-6); [PMC10794145](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10794145/); [github.com/google-deepmind/funsearch](https://github.com/google-deepmind/funsearch)
- **AlphaDev / "Faster sorting algorithms discovered using deep reinforcement learning"** — Google DeepMind. **Nature, published 7 June 2023** [V, nature.com]. **NOT an LLM** — it is an AlphaZero extension (deep RL) that plays "AssemblyGame," searching directly over **x86 assembly instructions**. Correctness: the game formulation requires the emitted program to pass sorting correctness tests on all input permutations (correctness is a hard constraint of the search, plus the discovered routines were separately verified before upstreaming). Results: new fixed-sort routines for sort-3/4/5 **integrated into the LLVM libc++ standard C++ sort** — the first change to that component in over a decade; **~70% faster for short sequences and ~1.7% faster for sequences above 250,000 elements**. **Language: x86 assembly, shipped into C++ standard library — C/C++ RELEVANT.** — [Nature s41586-023-06004-9](https://www.nature.com/articles/s41586-023-06004-9); [DeepMind blog](https://deepmind.google/blog/alphadev-discovers-faster-sorting-algorithms/); [PMC10247365](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10247365/)

### Inferences
- FunSearch and AlphaEvolve both make the *evaluator*, not the LLM, the source of truth — the LLM is a proposal distribution and the scored gate is what makes the system sound. This is precisely the user's "keep the edit only if replay gets faster" design, and it is the cleanest precedent to cite for the architecture.
- AlphaEvolve is the only entry here with both (a) an LLM proposer and (b) verified production-scale speed wins, so it is the strongest single citation for "LLM agent + measured gate works at scale."
- GI-Agent is the closest *published academic* analogue on C/C++ (MiniSAT), but it is a short workshop paper without headline speedup numbers.

### Gaps
- The AlphaEvolve white paper PDF did not parse; per-benchmark experimental detail (how many evaluator calls, variance across runs, exact evaluator design) is not captured here.
- GI-Agent's actual speedup on MiniSAT (C++) is not on the program page; the UCL preprint PDF would have it.

---

## Q3. Does any work use a RUNTIME PROFILE (perf, sampling profiler, hotspot ranking) to guide an LLM?

### Takeaway
**Yes — and this is now an active 2025–2026 line, so the user has direct precedent rather than a novelty claim.** The two closest works are **PerfAgent** (profiler-guided, verifier-in-the-loop, repository-level, explicitly argues profiler evidence beats timing alone for deciding what to optimize next) and **PRAGMA** (uses **Linux perf** and **Nsight Compute** metrics inside the LLM reasoning loop, with a dedicated agent that classifies bottlenecks).

### Cited Findings (all RECENT, 2025–2026)

- **PerfAgent: Profiler-Guided Iterative Refinement for Repository-Level Code Optimization** — Ryan Deng, Yuanzhe Liu, Bastian Lipka, Yao Ma, Xuhao Chen, Tim Kaler, Jatin Ganhotra. **arXiv:2607.19653**, submitted **22 July 2026**, cs.SE/cs.AI; **no conference venue listed — arXiv preprint** [V]. Method: a **profiler-guided, verifier-in-the-loop workflow wrapped around an off-the-shelf coding agent** (baseline comparison is OpenHands + GPT-5.1). Three named mechanisms: **(1) curated profiler summary, (2) selective test, (3) objective-driven controller.** Explicit framing of the failure modes it fixes: agents "miss bottlenecks hidden behind abstraction layers and native extensions, stop after shallow speedups, or insufficiently test the code patches," and it uses "**profiler evidence rather than timing alone to decide what to optimize next**." Acceptance criteria: a patch must preserve behavior, implement a real optimization, and approach expert-level speedup. Benchmarks: **GSO** and **SWE-fficiency-Lite**. Results: **39.2% expert-matching patches on GSO (vs 19.6% baseline)** and **74% on SWE-fficiency-Lite (vs 26%)** — "more than doubles the rate of expert-matching patches." Languages: real-world repositories; the abstract's mention of "native extensions" implies C/C++ extension modules behind Python, but the language breakdown is **UNVERIFIED**. No speedup multipliers or variance numbers in the abstract. — [arXiv:2607.19653](https://arxiv.org/abs/2607.19653)
- **PRAGMA: A Profiling-Reasoned Multi-Agent Framework for Automatic Kernel Optimization** — Kelun Lei, Hailong Yang, Huaitao Zhang, Xin You, Kaige Zhang, Zhongzhi Luan, Yi Liu, Depei Qian. **arXiv:2511.06345**, submitted 9 Nov 2025, revised 24 Nov 2025, cs.DC; **arXiv preprint, no venue** [V]. Method: multi-agent; a **Profiler Agent gathers low-level metrics from diverse profilers including Nsight Compute and Linux `perf`, across both CPU and GPU platforms**, and a **Conductor Agent interprets the profiling output and performs bottleneck classification**, feeding that into the generation loop; best-so-far versions are preserved across iterations (elitism). Benchmark: **KernelBench**. Results: **2.81× average speedup vs. Torch on CPU and 2.30× on GPU.** Targets GPU and CPU kernels (**CUDA/C++ implied; not confirmed on the abstract page — UNVERIFIED**). — [arXiv:2511.06345](https://arxiv.org/abs/2511.06345)
- **Agentic Auto-Scheduling: An Experimental Study of LLM-Guided Loop Optimization** — Massinissa Merouani, Islem Kara Bernou, Riyadh Baghdadi. **PACT 2025** (34th Intl. Conf. on Parallel Architectures and Compilation Techniques) [V, stated on arXiv:2511.00592 page]; submitted 1 Nov 2025, revised 27 Dec 2025. Method: **zero-shot LLM as an interactive optimization agent in a compiler feedback loop** — the LLM proposes loop transformations, the compiler returns **legality and measured performance feedback**, and the LLM refines. No fine-tuning. Benchmark: **PolyBench** (a C benchmark suite — **C RELEVANT**, though the abstract does not restate the language). Correctness: enforced by the compiler's transformation **legality check** (polyhedral legality), which is the strongest correctness story in this section. Results: **2.66× geometric-mean speedup on a single run; 3.54× with best-of-5 runs**; competitive with and often beating the **Pluto** polyhedral optimizer. — [arXiv:2511.00592](https://arxiv.org/pdf/2511.00592)
- **Agentic Code Optimization via Compiler-LLM Cooperation** — arXiv:2604.04238 [V that the arXiv entry exists; contents from search snippet only]. Reports that compiler-LLM cooperation "outperforms both existing compiler optimizations and level-specific LLM-based baselines, producing **speedups up to 1.25×**." Authors, venue, language **UNVERIFIED**. — [arXiv:2604.04238](https://arxiv.org/abs/2604.04238)
- **AutoPass: Evidence-Guided LLM Agents for Compiler Performance Tuning** — arXiv:2606.20373. "Evidence-guided" suggests measurement-driven gating. Details **UNVERIFIED** (search result only). — [arXiv:2606.20373](https://arxiv.org/pdf/2606.20373)
- **AI Coding Agents Need Better Compiler Remarks** — arXiv:2604.13927. Argues agents need richer compiler-side feedback (optimization remarks) — the compiler-diagnostic analogue of profile guidance. Details **UNVERIFIED**. — [arXiv:2604.13927](https://arxiv.org/pdf/2604.13927)
- KernelBench's own maintainers note that although frontier models match the PyTorch baseline in **under 20%** of cases out of the box, "**results can improve by leveraging execution and profiling feedback during iterative refinement**" — an independent statement that profile feedback is the lever. — [Simon Guo, "Towards Automated GPU Kernel Generation," Oct 2025](https://simonguo.tech/blog/2025-10-automated-gpu-kernels.html)

### Inferences
- The user's mechanism ("LLM agent + profiler + measured acceptance gate") is **not novel in the abstract** as of mid-2026 — PerfAgent is essentially the same architecture for Python-fronted repositories, and PRAGMA is the same for kernels. The defensible novelty must come from the *domain and gate design*: C/C++ source, fuzzing throughput, a **single up-front profile with a fixed corpus and deterministic replay** (rather than PerfAgent's re-profiling loop), and keeping only folds that beat the previous best replay time.
- PerfAgent's stated failure modes ("stop after shallow speedups," "insufficiently test the patches," "bottlenecks hidden behind abstraction layers and native extensions") are the best available published justification for the user's design choices, and should be cited as motivation.
- Agentic Auto-Scheduling is the only entry where correctness is guaranteed *structurally* (polyhedral legality) rather than by testing — a useful contrast point when the user argues about what their gate can and cannot guarantee.

### Gaps
- I did not find any work that uses a **sampling profiler on a fuzzing workload** or that ranks hotspots from a fixed replay corpus — the user's specific setup appears unpublished.
- PerfAgent's exact profiler (perf? py-spy? cProfile?) is not stated in the abstract; the full PDF would be needed.
- No paper found that publishes an ablation of "profile-guided hotspot ranking vs. no profile" holding everything else constant, which would be the cleanest citation for the value of the profile.

---

## Q4. How is correctness / semantic equivalence guaranteed?

### Takeaway
Essentially all of this literature relies on **testing, not proof**: unit tests bundled with the dataset (PIE), the repository's own test suite run separately from the timing workload (SWE-fficiency, PerfAgent), or a scored automated evaluator (FunSearch, AlphaEvolve). The only structural/semantic guarantees come from compiler legality checks (polyhedral auto-scheduling) and from RL formulations where correctness is a hard constraint of the search (AlphaDev). **No entry I found uses formal equivalence checking of LLM-produced C/C++ edits.**

### Cited Findings
- **PIE**: correctness by the **unit tests shipped with each of the 77k+ C++ pairs**; the paper also uses **gem5** so that timing noise cannot be confused with a real improvement. — [arXiv:2302.07867](https://arxiv.org/abs/2302.07867)
- **SWE-fficiency**: the cleanest separation in the literature — it "**verifies correctness using a repository's own tests**" and uses "**separate correctness and performance workloads**," explicitly distinguishing itself from earlier benchmarks that used unit-test runtime as a performance proxy. — [arXiv:2511.06090](https://arxiv.org/html/2511.06090v3)
- **PerfAgent**: "**verifier-in-the-loop**" plus a **selective test** mechanism; a patch is only counted if it preserves behavior, implements a real optimization, and approaches expert speedup. — [arXiv:2607.19653](https://arxiv.org/abs/2607.19653)
- **GSO**: the agent is given "a codebase **and performance test as a precise specification**"; success is measured against the expert developer's optimization. — [arXiv:2505.23671](https://arxiv.org/abs/2505.23671)
- **FunSearch**: a **systematic evaluator** that "guards against confabulations and incorrect ideas" scores every candidate program; nothing enters the population unscored. — [Nature s41586-023-06924-6](https://www.nature.com/articles/s41586-023-06924-6)
- **AlphaEvolve**: "**automated evaluation metrics**" that verify, run and score each proposed program; the TPU Verilog change additionally went through Google's existing hardware verification before integration. — [DeepMind blog](https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/)
- **AlphaDev**: correctness is a hard constraint inside AssemblyGame; discovered sort-3/4/5 routines were verified and upstreamed into LLVM's libc++. — [Nature s41586-023-06004-9](https://www.nature.com/articles/s41586-023-06004-9)
- **Agentic Auto-Scheduling (PACT 2025)**: the compiler returns **legality** feedback on each proposed loop transformation — a semantics-preserving guarantee from the polyhedral model rather than from tests. — [arXiv:2511.00592](https://arxiv.org/pdf/2511.00592)
- **SuperCoder**: reports a "**test-passing rate**" (e.g. 51.5% for Claude-opus-4; 95.0% for the fine-tuned model), i.e. test-based correctness on assembly programs; the abstract does not mention formal equivalence checking. — [arXiv:2505.11480](https://arxiv.org/abs/2505.11480)
- **ECO**: frames correctness only as something to be "minimiz[ed] correctness loss" against — i.e. it accepts some correctness degradation as a cost of speed, which is weaker than a hard gate. — [arXiv:2510.10517](https://arxiv.org/pdf/2510.10517)
- **MPCO (ASE'25 industry)**: reports that "**96% of the top-performing optimizations stem from meaningful edits**," implying post-hoc validation rather than a proof. — [arXiv:2508.01443](https://arxiv.org/html/2508.01443v2)

### Inferences
- The user's accept/reject gate is squarely in the mainstream: measured replay time for speed + tests for behavior. The literature gives no example of formal verification of LLM C/C++ performance edits, so the user cannot be faulted for not having one — but they should cite Agentic Auto-Scheduling and AlphaDev as the two existing examples of *stronger-than-testing* correctness, and state explicitly that their gate is empirical.
- A notable weakness across the field, which the user can position against: most benchmarks reuse the same workload for correctness and timing. SWE-fficiency and PerfAgent are the two that separate them, matching the user's "fixed corpus deterministic replay separate from validation" design.

### Gaps
- I found no work applying differential testing or translation validation to LLM performance edits in C/C++.

---

## Q5. Systems-level work: compiler optimization / pass ordering, GPU kernels, superoptimization

### Takeaway
Three sub-lines: (a) Meta's LLM-for-compiler line (LLVM IR, from C/C++) which is code-size- and pass-ordering-focused; (b) the KernelBench ecosystem, now the de-facto GPU-kernel benchmark with a large 2025–2026 follow-on family; (c) LLM superoptimization of assembly, where SuperCoder reports ~1.4–1.5× over `gcc -O3`.

### Cited Findings

**Compiler optimization / pass ordering**

- **Meta Large Language Model Compiler: Foundation Models of Compiler Optimization** — Meta AI. **arXiv:2407.02524 (July 2024)**, foundational [V that the arXiv entry and PDF exist]. Operates on **LLVM IR (from C/C++) — C/C++ RELEVANT**. Two capabilities: emulating the compiler (predicting optimized IR) and **flag/pass-list tuning**. Training data: **4.5M unoptimized IRs** used for pretraining were turned into flag-tuning examples; pass lists from random search were minimized by a three-step process — **redundant pass elimination, bubble sort, and insertion search** over the 167 search passes — yielding an **average pass-list length of 3.84**. Objective in the described flag-tuning setting is **binary size reduction**, not runtime. A version titled "**LLM Compiler: Foundation Language Models for Compiler Optimization**" appears in the ACM Digital Library at DOI **10.1145/3708493.3712691** — the **venue and year of that ACM version are UNVERIFIED** (the DOI prefix is consistent with an early-2025 ACM SIGPLAN-adjacent proceedings, likely CC 2025, but I did not confirm; do not assert it). — [arXiv:2407.02524](https://arxiv.org/pdf/2407.02524); [ar5iv HTML](https://ar5iv.labs.arxiv.org/html/2407.02524); [ACM DL PDF](https://dl.acm.org/doi/pdf/10.1145/3708493.3712691)
- **Large Language Models for Compiler Optimization** — Meta (Cummins et al.), **arXiv:2309.07062 (Sept 2023)**, the predecessor work: a 7B model trained to predict optimal LLVM pass lists directly from IR. Language: **LLVM IR / C-derived — C/C++ RELEVANT**. Author list and any conference venue **UNVERIFIED** (I saw only the PDF link). — [arXiv:2309.07062](https://arxiv.org/pdf/2309.07062)
- Non-LLM ML-for-compilers context, useful for framing: **POSET-RL: Phase ordering for Optimizing Size and Execution Time using Reinforcement Learning** (arXiv:2208.04238) and **The Next 700 ML-Enabled Compiler Optimizations** (arXiv:2311.10800). Both **UNVERIFIED** as to venue.

**GPU kernels**

- **KernelBench: Can LLMs Write Efficient GPU Kernels?** — Stanford Scaling Intelligence Lab. **arXiv:2502.10517**; benchmark first released **December 2024** [V that arXiv entry and repo exist; **author list UNVERIFIED** — I did not fetch the abstract page]. **250 tasks in 4 levels**: L1 = 100 single ops (convolutions, matmuls), L2 = 100 fused ops (conv+bias+ReLU), L3 = 50 full architectures (MobileNet, MiniGPT), L4 = 20 aspirational HuggingFace model tasks. Metric: **`fast_p`** = fraction of generated kernels that are **functionally correct AND exceed a speedup threshold p** over the PyTorch baseline — i.e. a built-in correctness-plus-measured-speedup gate, structurally identical to the user's accept/reject rule. Headline: frontier reasoning models "match the PyTorch baseline in **less than 20%** of cases" out of the box. **Language: CUDA C++ (plus Triton and other DSLs) — C/C++ RELEVANT.** — [arXiv:2502.10517](https://arxiv.org/abs/2502.10517); [github.com/ScalingIntelligence/KernelBench](https://github.com/ScalingIntelligence/KernelBench)
- **KernelLLM**: an 8B model fine-tuned from Llama 3.1 Instruct to translate PyTorch modules into **Triton** kernels, "competitive on KernelBench-Triton despite its smaller size." Attribution/venue **UNVERIFIED** (described in secondary coverage). — [Simon Guo blog](https://simonguo.tech/blog/2025-10-automated-gpu-kernels.html)
- 2025–2026 KernelBench follow-ons, all **UNVERIFIED beyond the arXiv identifier**: **STARK: Strategic Team of Agents for Refining Kernels** (arXiv:2510.16996), **KForge: Program Synthesis for Diverse AI Hardware Accelerators** (arXiv:2511.13274), **KernelBench-Verified: Do LLM-Generated Kernels Actually Beat PyTorch?** (arXiv:2607.16241 — directly relevant to the reliability question), **KernelBench-X** (arXiv:2605.04956), **ParallelKernelBench: Can LLMs Write Fast Multi-GPU Kernels?** (arXiv:2606.parallel-kernel-bench per alphaXiv; identifier looks malformed, treat with suspicion).
- **PRAGMA** (see Q3) is the profiling-driven entry in this family: **2.81× CPU / 2.30× GPU vs Torch on KernelBench**. — [arXiv:2511.06345](https://arxiv.org/abs/2511.06345)

**Superoptimization**

- **SuperCoder: Assembly Program Superoptimization with Large Language Models** — Anjiang Wei, Tarun Suresh, Huanmi Tan, Yinglun Xu, Gagandeep Singh, Ke Wang, Alex Aiken. **arXiv:2505.11480**, v1 16 May 2025, v4 8 Aug 2026; **no conference acceptance stated on the arXiv page** [V]. (An OpenReview entry exists at id=30iarHLvCS — venue **UNVERIFIED**; note some listings title it "Improving Assembly Code Performance with Large Language Models," so the title changed across versions.) Benchmark: **8,072 assembly programs averaging 130 lines**, a large jump over prior superoptimization work limited to "2–15 straight-line, loop-free programs." **Language: x86 assembly; whether the sources are C/C++ compilations is UNVERIFIED on the abstract page** (the `gcc -O3` baseline strongly implies C/C++ provenance). 23 LLMs evaluated. Correctness: reported as a **test-passing rate**. Results vs **`gcc -O3`**: Claude-opus-4 **51.5% pass rate, 1.43× average speedup**; Qwen2.5-Coder-7B-Instruct baseline **1.10×**; the fine-tuned SuperCoder model (RL with **PPO and GRPO**, reward combining **correctness and measured speedup**) reaches **95.0% correctness and 1.46× average speedup**. — [arXiv:2505.11480](https://arxiv.org/abs/2505.11480)

### Inferences
- KernelBench's `fast_p` metric is the single best-known formalization of the user's gate (correct AND faster by a threshold), and is worth citing directly as the metric design precedent.
- SuperCoder is the best precedent for *training* on a correctness+speedup reward, if the user ever wants to go beyond prompting.
- Meta's LLM Compiler line optimizes **code size**, not runtime, in its flag-tuning setting — the writer should not present it as a runtime-speedup result.

### Gaps
- I did not verify the ACM venue/year for the LLM Compiler paper; it must be checked in the ACM DL before citation.
- KernelBench's author list was not retrieved.

---

## Q6. Variance and reproducibility of LLM optimization results across repeated runs

### Takeaway
This is the strongest, most directly usable finding for the user: a **July 2026 audit shows that the leading performance-optimization benchmarks are substantially noise-dominated** — only **39/102 GSO** and **11/140 SWE-Perf** reference patches remain valid when replayed on different machines — which is precisely the argument for the user's deterministic-replay gate. Separately, PIE's use of gem5 and Agentic Auto-Scheduling's 2.66× single-run vs 3.54× best-of-5 gap quantify how much run-to-run LLM stochasticity matters.

### Cited Findings (RECENT 2026 first)

- **Are Performance-Optimization Benchmarks Reliably Measuring Coding Agents?** — Zhi Chen, Zhensu Sun, Yuling Shi, David Lo, Lingxiao Jiang. **arXiv:2607.01211**, submitted 1 July 2026, revised 16 July 2026, cs.SE; **arXiv preprint, no venue** [V]. Method: replayed the **official reference patches** of **GSO, SWE-Perf and SWE-fficiency across different Google Cloud machine types**. Findings:
  - Reference patches satisfied the benchmarks' own validity rules in every cross-machine replay for only **39/102 GSO tasks (~38%)**, **11/140 SWE-Perf tasks (~8%)**, and **411/498 SWE-fficiency tasks (~82%)**.
  - SWE-Perf is worst because "**many reference patches produce close-to-zero runtime changes**," making the measurement noise-dominated.
  - Across eight shared public submissions, **official rankings disagreed on 9 of 28 pairwise comparisons** between benchmarks.
  - Across 10 submissions per task, at least one submission matched or exceeded the reference patch on **85.3% of replay-valid tasks (384/450)**, and **99.8% (449/450)** beat the unoptimized baseline.
  - Conclusion framing: "leaderboard scores can conflate runtime instability, benchmark-specific scoring rules, and how many tasks are already solved by at least one public submission."
  — [arXiv:2607.01211](https://arxiv.org/abs/2607.01211)
- **Agentic Auto-Scheduling (PACT 2025)** quantifies LLM run-to-run spread directly: **2.66× geometric-mean speedup on a single run vs 3.54× with best-of-5 runs** on PolyBench — a ~33% relative gap purely from resampling. The abstract does not give a standard deviation. — [arXiv:2511.00592](https://arxiv.org/pdf/2511.00592)
- **PIE** motivated its use of **gem5** by measurement variability; per a search snippet from the PIE OpenReview PDF, when benchmarking **identical programs** the authors observed a **mean "speedup" of 1.12× with standard deviation 0.36** — i.e. pure noise can look like a 12% win with a very wide spread. **Caveat: this number came from a search snippet over openreview.net/pdf?id=ix7rLVHXyY, not from a fetch of the PDF body — verify before quoting.** — [PIE OpenReview PDF](https://openreview.net/pdf?id=ix7rLVHXyY)
- General mitigation practices reported across this literature (from a search-snippet synthesis, individually **UNVERIFIED**): isolating experiment environments, running each benchmark **10 times**, using Docker containers for a consistent execution environment, and running with no other processes active. One source attributes containerized measurement variance to two independent causes — **scheduler jitter plus interpreter behavior within a container, and CPU-state variation across containers** — and mitigates by executing workloads across multiple fresh container instances. — search synthesis over [arXiv:2606.25530](https://arxiv.org/pdf/2606.25530) and related; treat as a practice summary, not a single citable claim.
- An observation framing variance as informative rather than purely harmful: "variance in speedups is a direct consequence of LLMs exploring different pathways and converging to multiple, distinct performance optima, underscoring the value of **multi-run strategies** to increase the probability of finding better-performing optima." Source attribution within the search results was ambiguous — **UNVERIFIED**, most likely from the Agentic Auto-Scheduling or ReVEL (arXiv:2604.04940) papers.
- **KernelBench-Verified: Do LLM-Generated Kernels Actually Beat PyTorch?** (arXiv:2607.16241) is, by title, the GPU-kernel analogue of this reliability audit. Contents **UNVERIFIED**.
- **SWE-ABS: Adversarial Benchmark Strengthening Exposes Inflated Success Rates on Test-based Benchmarks** — ICML 2026 poster [V-listing, icml.cc/virtual/2026/poster/62669]. Not performance-specific but directly about inflated success rates on test-gated coding benchmarks. — [ICML 2026 poster](https://icml.cc/virtual/2026/poster/62669)

### Inferences
- The Chen et al. audit is the paper to cite as the motivation for the user's **deterministic replay** design: it demonstrates empirically that wall-clock gates on shared/cloud machines frequently fail to reproduce, and that near-zero-effect reference patches are the main culprit. The user's fixed-corpus deterministic replay and "must beat the previous best" rule are direct mitigations of exactly these two failure modes.
- The combination of PIE's gem5 choice (2024) and Chen et al.'s cross-machine audit (2026) establishes a clean two-point narrative: the field has known about timing noise since the beginning, and the repo-level benchmarks that replaced simulation have inherited the problem.
- Almost no paper reports a **distribution** of achieved speedup across repeated *agent* runs; the norm is best-of-k or a single mean. That is a real gap the user's work could fill cheaply and cite as a contribution.

### Gaps
- I found **no paper that reports a full run-to-run distribution (mean ± sd, or a histogram) of end-to-end achieved speedup for an LLM optimization agent across repeated identical invocations.** Best-of-5 vs single-run (Agentic Auto-Scheduling) is the closest.
- The PIE 1.12× ± 0.36 identical-program figure needs confirmation from the PDF body.

---

## Q7. Industrial deployments at scale (Google, Meta, Microsoft)

### Takeaway
Only **Google DeepMind's AlphaEvolve** has publicly reported LLM-driven performance optimization deployed at production scale with quantified results. **Meta's** public contribution is the LLM Compiler *models* (research artifacts, code-size objective) rather than a reported deployment. A smaller UK industrial deployment (**TurinTech ARTEMIS**, ASE'25 industry showcase) reports real numbers. **I found no comparable public Microsoft result.**

### Cited Findings
- **Google / DeepMind — AlphaEvolve (2025)**, deployed inside Google: **0.7% of Google's worldwide compute continuously recovered** through a Borg scheduling heuristic; **a Verilog TPU arithmetic-circuit simplification** headed into an upcoming TPU; **23% speedup on a critical Gemini kernel → 1% reduction in total Gemini training time**; **up to 32.5% speedup on a FlashAttention kernel**. — [DeepMind blog](https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/)
- **Meta — LLM Compiler** (arXiv:2407.02524, July 2024): released as **foundation models for compiler optimization** built on LLVM IR with 4.5M pretraining IRs; the reported task is binary-size flag tuning, not a production runtime-speedup deployment. — [arXiv:2407.02524](https://arxiv.org/pdf/2407.02524)
- **TurinTech / ARTEMIS — MPCO: "Tuning LLM-based Code Optimization via Meta-Prompting: An Industrial Perspective"** — Jingzhi Gong, Rafail Giavrimis, Paul Brookes, Vardan Voskanyan, Fan Wu, Mari Ashiga, Matthew Truscott, Mike Basios, Leslie Kanthan, Jie Xu, Zheng Wang. arXiv:2508.01443 (2 Aug 2025; rev. 3 Oct 2025), **accepted at ASE'25 Industry Showcase** [V, stated on the arXiv page]. Method: **meta-prompting** — automatically synthesizing task-specific optimization prompts per LLM from project metadata, task requirements and model-specific context, replacing manual per-model prompt engineering. Evaluation: **five real-world codebases with 366 hours of runtime benchmarking**. Result: **up to 19.06% improvement** with the best statistical rank across all systems vs. baseline methods; **96% of top-performing optimizations stem from meaningful edits**. Language **UNVERIFIED** (not stated in the abstract). — [arXiv:2508.01443](https://arxiv.org/html/2508.01443v2)
- Secondary reporting claims AlphaEvolve has since been rolled out more broadly across Google's data centers, TPUs and training pipelines. — [The Agent Report, May 2026](https://the-agent-report.com/2026/05/deepmind-alphaevolve-mainstream/) (**low-quality secondary source; do not cite for specifics**)
- A 2026 systems-industry position paper, **"GenAI for Systems: Recurring Challenges and Design Principles from Software to Silicon"** (arXiv:2602.15241), appears to survey exactly this deployment space. Contents and authorship **UNVERIFIED**. — [arXiv:2602.15241](https://arxiv.org/pdf/2602.15241)

### Inferences
- For the user's related-work section, AlphaEvolve is the only citation that supports "this mechanism produces real, deployed wins," and its numbers (0.7% fleet compute, 23% kernel, 32.5% FlashAttention) are the ones worth quoting.
- The industrial results cluster around single-digit-to-~30% improvements on already-tuned production code, in contrast to the 2–9× figures on competitive-programming and kernel benchmarks. If the user's fuzzing-throughput gains are in the tens of percent, that is consistent with the *industrial* regime, not the benchmark regime — worth saying explicitly so the numbers are not read as underwhelming.

### Gaps
- **No public Microsoft Research deployment of LLM-driven runtime performance optimization was found.** I searched the general space but did not run a Microsoft-specific query; this is an unexplored corner.
- No public Meta deployment result (as opposed to model release) was found.
- The AlphaEvolve white paper's methodological detail (evaluator design, number of candidate evaluations per win) is not captured, because the PDF did not parse.

---

## Cross-cutting summary table (for the writer)

| Work | Year / Venue | Method | Language | Correctness check | Benchmark | Speedup |
|---|---|---|---|---|---|---|
| PIE (Shypula et al.) | ICLR 2024 Spotlight [V] | Prompting + retrieval + perf-conditioning + self-play FT | **C++** | Unit tests; gem5 timing | PIE (77k C++ pairs, CodeNet) | 6.86× mean @8 gens; 9.64× best |
| GSO (Shetty et al.) | 2025, NeurIPS'25 per repo [V-listing] | Benchmark for SWE-agents | Mixed (unclear) | Performance test as spec | GSO, 102 tasks / 10 codebases | <5% success rate |
| SWE-Perf | ICML 2026 [V] | Benchmark | Python (likely) | Performance-related tests | 140 PR-derived instances | Large gap vs experts (no number) |
| SWE-fficiency | ICML 2026 [V-listing] | Benchmark | Python + native | Repo's own tests; **separate perf workload** | 498 tasks / 9 repos | — |
| FormulaCode | ICML (camera-ready) [V-listing] | Benchmark, multi-objective | Python | — (not in abstract) | 957 bottlenecks, 264.6 workloads/task | — |
| **PerfAgent** | arXiv 2607.19653, Jul 2026 [V] | **Agentic + profiler-guided + verifier-in-loop** | Repos w/ native ext. | Selective test + verifier | GSO, SWE-fficiency-Lite | 39.2% vs 19.6% (GSO); 74% vs 26% |
| **PRAGMA** | arXiv 2511.06345, Nov 2025 [V] | **Multi-agent + Nsight Compute + Linux perf** | CUDA/C++ (implied) | — (not in abstract) | KernelBench | 2.81× CPU / 2.30× GPU vs Torch |
| Agentic Auto-Scheduling | PACT 2025 [V] | Zero-shot LLM in compiler loop | **C** (PolyBench) | **Compiler legality check** | PolyBench | 2.66× single / 3.54× best-of-5 |
| SuperCoder | arXiv 2505.11480 [V], no venue | Prompting + RL (PPO/GRPO) fine-tune | x86 asm (from C/C++?) | Test-passing rate | 8,072 asm programs | 1.43× (Claude-opus-4), 1.46× (FT) vs gcc -O3 |
| KernelBench | arXiv 2502.10517, Dec 2024 [V] | Benchmark; `fast_p` = correct AND faster | **CUDA C++**/Triton | Functional check in `fast_p` | 250 tasks, 4 levels | <20% match PyTorch baseline |
| ECO | arXiv 2510.10517, Oct 2025 [V] | Performance-aware prompting | Unclear | "minimizing correctness loss" | Unclear | up to 7.81× |
| GI-Agent | GI 2026 @ ICSE 2026 [V] | LLM-driven genetic improvement + reflections | **C++ (MiniSAT)**, Java | Compile + runtime feedback | SAT4J, MiniSAT | Qualitative only |
| AlphaEvolve | DeepMind, May 2025 [V] | Evolutionary + Gemini ensemble + auto-evaluator | Python, Verilog | Automated scoring evaluators | Internal Google systems | 0.7% fleet compute; 23% kernel; 32.5% FlashAttention |
| FunSearch | Nature, Dec 2023 [V] | Evolutionary + frozen LLM + evaluator | Python | Systematic evaluator | Cap set, online bin packing | N/A (solution quality) |
| AlphaDev | Nature, Jun 2023 [V] | **Deep RL (not LLM)**, AlphaZero over asm | x86 asm → **LLVM libc++** | Correctness as search constraint | libc++ sort | ~70% short seqs; ~1.7% >250k |
| Meta LLM Compiler | arXiv 2407.02524, Jul 2024 [V]; ACM version venue UNVERIFIED | Foundation model, flag/pass tuning | **LLVM IR (C/C++)** | Compiler semantics | LLVM IR corpus | Code size, not runtime |
| MPCO (ARTEMIS) | ASE'25 Industry Showcase [V] | Meta-prompting | Unclear | Post-hoc validation (96% meaningful) | 5 real codebases, 366h | up to 19.06% |
| Benchmark reliability audit (Chen et al.) | arXiv 2607.01211, Jul 2026 [V] | Cross-machine replay audit | — | — | GSO / SWE-Perf / SWE-fficiency | 39/102, 11/140, 411/498 replay-valid |
