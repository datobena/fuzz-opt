# LLMs and AI Agents Applied to Fuzzing and Automated Vulnerability Discovery Pipelines

**Scope note for the report writer.** This map is organized by *which part of the fuzzing loop the LLM touches*. Within each section, **[RECENT: 2025–2026]** work is listed first, then **[2023–2024]** work. Venue-verification status is marked per entry:

- **VERIFIED** = venue/year confirmed against a primary source reached in this session (ACM DL DOI page, USENIX page, ICLR virtual site, conf.researchr.org program page, or the publisher PDF).
- **HIGH-CONF** = venue reported consistently by search results tied to a publisher URL, but the publisher page itself was not directly fetched in this session.
- **arXiv-only (NOT PEER-REVIEWED)** = no venue found; treat as preprint.
- **UNVERIFIED** = venue claimed by a secondary source only; do not repeat without checking.

Today's date is 2026-09-26, so "2026 work" here includes papers posted through September 2026.

---

## Key Question 1: Harness / fuzz-driver generation (OSS-Fuzz-Gen, Fuzz4All, PromptFuzz, CKGFuzzer, and 2025–2026 successors) — reported coverage gains and how measured

### Takeaway
Harness/driver generation is by far the most crowded part of the LLM-in-fuzzing space, and it is the only part with an industrial-scale deployment (Google's OSS-Fuzz-Gen). Reported gains are almost universally measured as **line/branch/edge coverage delta against human-written or prior-tool harnesses**, plus **compile/build success rate** and **crash counts**; none of these papers report or optimize **executions-per-second of the target**.

### Cited Findings

**[RECENT: 2025–2026]**

- **OSS-Fuzz-Gen** (Google) is the production system: a multi-agent, AI-augmented pipeline for automated fuzz-driver generation at scale, built on OSS-Fuzz + Fuzz Introspector, which identifies under-fuzzed code and prompts an LLM to write a fuzz target, then measures coverage change and crashes. — [google/oss-fuzz-gen](https://github.com/google/oss-fuzz-gen); [OSS-Fuzz docs: Fuzz target generation using LLMs](https://google.github.io/oss-fuzz/research/llms/target_generation/)
- OSS-Fuzz-Gen reported results: valid fuzz targets generated for **160 C/C++ projects**, with a **maximum line-coverage increase of 29%** over existing human-written targets; experiments span **1300+ benchmarks from 297 open-source projects**. — [emergentmind OSS-Fuzz-Gen topic page](https://www.emergentmind.com/topics/oss-fuzz-gen) (aggregator; **the underlying numbers should be re-checked against the OSS-Fuzz blog/repo before citing**)
- OSS-Fuzz-Gen component results reported: an LLM-driven **Function Analyzer** raises the *Constraint Satisfaction Ratio* from **38.9% → 63.1%**, and a **Crash Validation Agent** filters up to **65%** of spurious crashes. — [emergentmind OSS-Fuzz-Gen topic page](https://www.emergentmind.com/topics/oss-fuzz-gen)
- **FalseCrashReducer: Mitigating False Positive Crashes in OSS-Fuzz-Gen Using Agentic AI** — arXiv:2510.02185 (Oct 2025). Adds constraint-based driver generation and context-based crash validation to OSS-Fuzz-Gen; reported to reduce spurious crashes by up to 8% and cut reported crashes by more than half. **arXiv-only (NOT PEER-REVIEWED)** as far as this search found. — [arXiv:2510.02185](https://arxiv.org/abs/2510.02185)
- Google's cumulative claim for AI-generated targets in OSS-Fuzz: improved code coverage across **272 C/C++ projects, adding over 370,000 lines of newly covered code**, and **26 new vulnerabilities** found with AI-generated/enhanced fuzz targets (incl. one in OpenSSL). — [OSS-Fuzz blog: Introducing LLM-based harness synthesis for unfuzzed projects](https://blog.oss-fuzz.com/posts/introducing-llm-based-harness-synthesis-for-unfuzzed-projects/); [The Hacker News summary](https://thehackernews.com/2024/11/googles-ai-powered-oss-fuzz-tool-finds.html)
- **HarnessAgent: Scaling Automatic Fuzzing Harness Construction with Tool-Augmented LLM Pipelines** — arXiv:2512.03420 (Dec 2025; v1/v3 online). Rule-based error minimization + hybrid symbol-retrieval pipeline, targeting **OSS-Fuzz projects**. Reported: **~20% improvement in three-shot success rate** over SOTA, reaching **87% (C) / 81% (C++)**; **>75% of generated harnesses increased target-function coverage**, with improvement exceeding 10%. **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2512.03420](https://arxiv.org/html/2512.03420)
- **FuzzAgent: Multi-Agent System for Evolutionary Library Fuzzing** — arXiv:2605.14431 (May 2026). Agents for harness generation, execution, crash triage; a Coverage Analyzer identifies coverage bottlenecks and a Harness Generator writes targeted harnesses for them. Reported: **45–191% more branch coverage** than four baselines on **20 C/C++ libraries**, **102 real bugs** surfaced. **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2605.14431](https://arxiv.org/pdf/2605.14431)
- **MASFuzzer: Fuzz Driver Generation and Adaptive Scheduling via Multidimensional API Sequences** — arXiv:2604.17977 (Apr 2026). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2604.17977](https://arxiv.org/pdf/2604.17977)
- **Scheduzz: Constraint-based Fuzz Driver Generation with Dual Scheduling** — arXiv:2507.18289 (Jul 2025). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2507.18289](https://arxiv.org/pdf/2507.18289)
- **Coverage-Guided Multi-Agent Harness Generation for Java Library Fuzzing** — arXiv:2603.08616 (Mar 2026). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2603.08616](https://arxiv.org/pdf/2603.08616)
- **Quality-Assured Fuzz Harness Generation via the Four Principles Framework** — arXiv:2605.21824 (May 2026). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2605.21824](https://arxiv.org/pdf/2605.21824)
- **Automatic, Expressive, and Scalable Fuzzing with Stitching** — arXiv:2602.18689 (Feb 2026). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2602.18689](https://arxiv.org/pdf/2602.18689)
- **AI-powered fuzzing with the GitHub Security Lab Taskflow Agent** — GitHub engineering blog; an agent that writes and maintains fuzz targets, framed explicitly as removing "the historical bottleneck — humans writing targets." **Industry blog, not peer-reviewed.** — [github.blog](https://github.blog/security/application-security/ai-powered-fuzzing-with-the-github-security-lab-taskflow-agent/)

**[2023–2024 foundations]**

- **Fuzz4All: Universal Fuzzing with Large Language Models** — Chunqiu Steven Xia, Matteo Paltenghi, Jia Le Tian, Michael Pradel, Lingming Zhang. **ICSE 2024**, DOI 10.1145/3597503.3639121. **VERIFIED** (ACM DL PDF). Uses an LLM as both input generator and mutation engine via autoprompting + LLM-powered fuzzing loop, across many SUT languages/systems. — [ACM DL PDF](https://dl.acm.org/doi/pdf/10.1145/3597503.3639121); [project site](https://fuzz4all.github.io/); [author PDF](https://software-lab.org/publications/icse2024_Fuzz4All.pdf)
- **PromptFuzz: Prompt Fuzzing for Fuzz Driver Generation** — arXiv:2312.17677; reported as **ACM CCS 2024** (Salt Lake City, Oct 14–18 2024). **HIGH-CONF** (ACM DL page not directly fetched in this session). Coverage-guided fuzzing *of the prompt space* to produce library fuzz drivers exercising diverse API combinations. — [arXiv:2312.17677](https://arxiv.org/pdf/2312.17677)
- **CKGFuzzer: LLM-Based Fuzz Driver Generation Enhanced By Code Knowledge Graph** — arXiv:2411.11532; reported as **ICSE 2025 Companion (IEEE/ACM 47th ICSE: Companion Proceedings)**. **HIGH-CONF**. — [arXiv:2411.11532](https://arxiv.org/pdf/2411.11532)
- **How Effective Are They? Exploring Large Language Model Based Fuzz Driver Generation** — arXiv:2307.12469; appears in **ISSTA 2024** (DOI 10.1145/3650212.3680355). **HIGH-CONF** (ACM DL PDF URL observed). The key empirical study of LLM fuzz-driver quality; measures effectiveness by driver validity + coverage. — [ACM DL PDF](https://dl.acm.org/doi/pdf/10.1145/3650212.3680355); [arXiv](https://arxiv.org/pdf/2307.12469)
- **Automated Generation and Compilation of Fuzz Driver Based on Large Language Models** — CSAE/ICCSIE 2024, DOI 10.1145/3689236.3689272. **HIGH-CONF**. Reports LLM drivers achieve "similar or slightly better coverage" than manual drivers on a substantial portion of targets. — [ACM DL](https://dl.acm.org/doi/10.1145/3689236.3689272)
- **Performance Comparison of Prompt Engineering and Fine-Tuning Approaches for Fuzz Driver Generation Using Large Language Models** — Springer chapter, DOI 10.1007/978-3-031-96093-2_12. **HIGH-CONF**. — [Springer](https://link.springer.com/chapter/10.1007/978-3-031-96093-2_12)

### Inferences
- The *universal* evaluation currency in this subfield is **coverage (line/branch/edge) and compile-success rate**, measured over fixed wall-clock campaigns (typically 24h) against human-written harnesses or a prior LLM harness generator. **Throughput (exec/s) is not an evaluated axis anywhere in this cluster**, which means an "LLM for fuzzing speed" project is not in competition with any of these on metrics.
- Because OSS-Fuzz-Gen harnesses are generated *for* OSS-Fuzz projects and merged upstream, an agent that instead rewrites the *project source under* an existing harness occupies a genuinely disjoint slot in the same infrastructure.

### Gaps
- The exact citation for the OSS-Fuzz-Gen system paper (if one exists beyond the repo, blog posts, and FalseCrashReducer) was not pinned down; the "29% max line-coverage increase / 160 projects / 1300+ benchmarks" and "38.9%→63.1% constraint satisfaction / 65% spurious-crash filtering" figures came from an aggregator page and should be re-sourced to the OSS-Fuzz blog, the repo README, or FalseCrashReducer before publication.
- Whether OSS-Fuzz-Gen's scoring ever penalizes slow harnesses (e.g., via the OSS-Fuzz "ideal fuzz target should be fast" guidance) was not established.

---

## Key Question 2: Seed and input generation (SeedSmith, LLM seed synthesis, grammar/structure inference) — and which use ARVO

### Takeaway
LLM seed synthesis is the second-largest cluster and the one that reports the largest **time-to-bug** speedups (order-of-magnitude on Magma), which makes it the closest existing work *in metric* to a throughput project — but the speedup comes from **better inputs**, never from a faster target. **None of the seed-generation papers found use ARVO**; ARVO appears almost exclusively in the *patching/benchmark* cluster (Key Questions 4 and 6).

### Cited Findings

**[RECENT: 2025–2026]**

- **SeedSmith: LLM-Driven Seed Synthesis for Directed Fuzzing** — Junmin Zhu et al., arXiv:2607.08949 (Jul 2026). **arXiv-only (NOT PEER-REVIEWED)**. Agentic pipeline mimicking an analyst: from a sink, iteratively explore the codebase, resolve indirect calls, identify crash preconditions, synthesize concrete inputs satisfying them. Three stages: target preparation (index functions, build call graphs, instrument with sanitizers), an Analysis Agent with tool-assisted retrieval, and seed synthesis. **Evaluation: Magma benchmark**; reported **geometric-mean crash-time speedups of 11.51× (AFL++) to 14.66× (AFLGo)** over default seeds; seeds are fuzzer-agnostic (a front-end, no fuzzer modification). — [arXiv:2607.08949](https://arxiv.org/abs/2607.08949); [HTML](https://arxiv.org/html/2607.08949)
- **SeedAIchemy: LLM-Driven Seed Corpus Generation for Fuzzing** — arXiv:2511.12448 (Nov 2025). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2511.12448](https://arxiv.org/abs/2511.12448)
- **ELFuzz: Efficient Input Generation via LLM-driven Synthesis Over Fuzzer Space** — Chuyang Chen et al. (OSU SecLab). **USENIX Security 2025 (34th USENIX Security Symposium)**. **VERIFIED** ([USENIX presentation page](https://www.usenix.org/conference/usenixsecurity25/presentation/chen-chuyang); [ACM DL proceedings entry](https://dl.acm.org/doi/10.5555/3766078.3766401)). LLM-driven evolutionary synthesis of *generation-based fuzzers* (i.e., the LLM writes the input generator, not the inputs). Reported: up to **+418.5% coverage** and up to **+216.7% more injected bugs triggered** vs. SOTA; fuzzer-space search contributes up to 62.5% of the gain; a 14-day campaign on cvc5 found **five 0-days** (three exploitable). Artifact: [OSUSecLab/elfuzz](https://github.com/OSUSecLab/elfuzz)
- **Low-Cost and Comprehensive Non-textual Input Fuzzing with LLM-Synthesized Input Generators** — arXiv:2501.19282 (Jan 2025). Same "LLM writes the generator, not the input" pattern, for binary/non-textual formats. **arXiv-only (NOT PEER-REVIEWED)** per this search. — [arXiv:2501.19282](https://arxiv.org/pdf/2501.19282)
- **Hybrid Language Processor Fuzzing via LLM-Based ...** — Yupeng Yang et al., **USENIX Security 2025**. **VERIFIED** (USENIX proceedings PDF). — [usenixsecurity25-yang-yupeng.pdf](https://www.usenix.org/system/files/usenixsecurity25-yang-yupeng.pdf)
- **FunFuzz: An LLM-Powered Evolutionary Fuzzing Framework** — arXiv:2605.02789 (May 2026). **arXiv-only (NOT PEER-REVIEWED)**. Compiler fuzzing; reported up to **+27.1% coverage on GCC C targets, +31.0% C++, +9.3% Clang C**, in 24-hour campaigns; uses DeepSeek-Coder-V2-Lite-Base, temp 1.0, top-p, 512 max tokens, served via vLLM. — [arXiv:2605.02789](https://arxiv.org/html/2605.02789v1)
- **ReFuzzer: Feedback-Driven Approach to Enhance Validity of LLM-Generated Test Programs** — arXiv:2508.03603 (Aug 2025). Local-LLM feedback loop validating/filtering erroneous generated programs before execution. **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2508.03603](https://arxiv.org/html/2508.03603)
- **SDLLMFuzz: Dynamic-static LLM-assisted greybox fuzzing for structured input programs** — arXiv:2604.17750 (Apr 2026). Reports faster time-to-bug than baselines at 24h and 48h. Ablation reportedly finds **LLM-based seed generation is the most critical factor**, with static crash feedback and mutation optimization secondary. **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2604.17750](https://arxiv.org/pdf/2604.17750)
- **FuzzPilot: Plateau-Triggered Recipe Validation for Structured Text Fuzzing** — arXiv:2605.26539 (May 2026). Notable for explicitly quantifying the throughput cost of in-loop LLMs (see Key Question 3). **arXiv-only**. — [arXiv:2605.26539](https://arxiv.org/pdf/2605.26539)

**[2023–2024]**

- **ISC4DGF: Enhancing Directed Grey-box Fuzzing with LLM-Driven Initial Seed Corpus Generation** — arXiv:2409.14329 (Sep 2024). **arXiv-only (NOT PEER-REVIEWED)** per this search. — [arXiv:2409.14329](https://arxiv.org/pdf/2409.14329)
- **Harnessing Large Language Models for Seed Generation in Greybox Fuzzing** — arXiv:2411.18143 (Nov 2024). **arXiv-only (NOT PEER-REVIEWED)** per this search. — [arXiv:2411.18143](https://arxiv.org/pdf/2411.18143)
- **Large Language Models are Zero-Shot Fuzzers: Fuzzing Deep-Learning Libraries via Large Language Models** (TitanFuzz) — arXiv:2212.14834; ISSTA 2023. **HIGH-CONF** (venue not fetched this session). The origin point of "LLM as input generator." — [arXiv:2212.14834](https://arxiv.org/pdf/2212.14834)
- **Fuzzing BusyBox: Leveraging LLM and Crash Reuse for Embedded Bug Unearthing** — USENIX (;login: / Security). — [USENIX](https://www.usenix.org/publications/loginonline/fuzzing-busybox-leveraging-llm-and-crash-reuse-embedded-bug-unearthing)

### Inferences
- Seed-generation papers benchmark on **Magma**, **compiler/DL-library targets**, or bespoke library sets — **not ARVO**. A project evaluated by **time-to-bug on ARVO historical bugs** is therefore methodologically novel even within the seed-generation neighborhood, though the *metric* (time-to-crash speedup, geometric mean) is directly comparable to SeedSmith's.
- SeedSmith is the most important comparison point for a throughput project: it is the strongest published "make the fuzzer find the bug sooner via LLM, without touching the fuzzer" result, and its 11.5–14.7× geomean crash-time speedup is the number a throughput approach would be measured against rhetorically.

### Gaps
- No LLM seed/grammar-inference paper found that evaluates on ARVO. If one exists it did not surface under the queries used.
- Exact venue status for ISC4DGF, SeedAIchemy, and the 2411.18143 seed paper was not confirmed (they may have since appeared at a venue).

---

## Key Question 3: LLM-guided mutation operators or scheduling inside the fuzzer itself

### Takeaway
This is the part of the loop where the literature has explicitly hit the **throughput wall** — several papers state outright that in-loop LLM calls destroy fuzzer throughput, and the field's response has been to *reduce LLM call frequency*, never to make the target faster. This is the strongest existing evidence that the throughput axis is recognized as a problem but attacked only from the LLM-scheduling side.

### Cited Findings

**[RECENT: 2025–2026]**

- **Quantified throughput wall:** "Inserting a single 100 ms LLM call per mutation drops throughput by three orders of magnitude"; on small parsers such as cJSON a 4-core x86_64 host sustains roughly **13,000 execs/sec per worker**. — [FuzzPilot, arXiv:2605.26539](https://arxiv.org/pdf/2605.26539)
- **Mitigations documented in the literature:** (a) offline/online separation — LLM does semantic reasoning offline while the fuzzer keeps high-throughput exploration; (b) parallel execution (~3.2× speedup at n=8 instances); (c) **stagnation-triggered LLM intervention** — monitor seed dirs and only invoke the LLM when no new seed appears for ~2 minutes; (d) one system reports **8.83M test cases with only 5.5% runtime overhead** vs. baseline fuzzing. — synthesized from [FuzzPilot](https://arxiv.org/pdf/2605.26539), [LLM-Assisted Model-Based Fuzzing of Protocol Implementations, arXiv:2508.01750](https://arxiv.org/html/2508.01750v1), [MALF, arXiv:2510.02694](https://arxiv.org/html/2510.02694v1) (**the 5.5%-overhead figure is from a search-result synthesis and should be attributed to a specific paper before citing**)
- **LLAMAFUZZ: Large Language Model Enhanced Greybox Fuzzing** — Hongxiang Zhang et al., arXiv:2406.07714; **AST 2026 (IEEE/ACM International Conference on Automation of Software Test)**. **VERIFIED** ([AST 2026 program page](https://conf.researchr.org/details/ast-2026/ast-2026-papers/16/LLAMAFUZZ-Large-Language-Model-Enhanced-Greybox-Fuzzing)). Fine-tuned LLM as a structured-data mutator inside greybox fuzzing. — [arXiv:2406.07714v2](https://arxiv.org/pdf/2406.07714v2)
- **Locus: Agentic Predicate Synthesis for Directed Fuzzing** — Jie Zhu et al. **ICSE 2026 (IEEE/ACM 48th ICSE)**, DOI 10.1145/3744916.3773102. **VERIFIED** ([ACM DL](https://dl.acm.org/doi/10.1145/3744916.3773102)). An LLM agent synthesizes and validates **intermediate predicates** (compiler- and symbolic-execution-checked, constrained to strictly relax target states) that are *inserted into the target* to guide directed fuzzing. Reported: **70.3× average speedup for directed fuzzers (up to 214.2× on SelectFuzz)** and **~13× for coverage-guided fuzzers**. — [arXiv:2508.21302](https://arxiv.org/pdf/2508.21302)
- **Semantic-Aware Fuzzing: An Empirical Framework for LLM-Guided, Reasoning-Driven Input Mutation** — arXiv:2509.19533 (Sep 2025). **arXiv-only**. — [arXiv:2509.19533](https://arxiv.org/pdf/2509.19533)
- **Hybrid Fuzzing with LLM-Guided Input Mutation and Semantic Feedback** — arXiv:2511.03995 (Nov 2025). **arXiv-only**. — [arXiv:2511.03995](https://arxiv.org/html/2511.03995)
- **Beyond Imprecise Distance Metrics: Trace-Guided Directed Greybox Fuzzing via LLM-Predicted Call Stacks** — arXiv:2510.23101 (Oct 2025). LLM predicts call stacks to replace distance metrics in DGF scheduling. **arXiv-only**. — [arXiv:2510.23101](https://arxiv.org/pdf/2510.23101)
- **Directed Greybox Fuzzing via Large Language Model** (HGFuzzer) — Hanxiang Xu et al., arXiv:2505.03425 (May 2025). LLM reads the call chain to the target, writes a small path-fixing harness, generates a path-satisfying seed, **and writes a custom mutator** aimed at the trigger condition. Reported: **17/20 known vulnerabilities triggered** in an open-source C/C++ library benchmark, 11 within the first minute; **≥24.8× speedup** over three directed fuzzers. **arXiv-only (NOT PEER-REVIEWED)** per this search. — [arXiv:2505.03425](https://arxiv.org/pdf/2505.03425)
- **State-Aware Fuzzing of JavaScript Engines with LLM-Guided Instrumentation** — arXiv:2609.24550 (Sep 2026). Notable because the LLM decides **instrumentation** placed in the target — again for signal, not speed. **arXiv-only**. — [arXiv:2609.24550](https://arxiv.org/html/2609.24550)
- **Large Language Model assisted Hybrid Fuzzing** (HyllFuzz) — arXiv:2412.15931. LLM substitutes for the concolic solver; reported **3–19× faster than concolic execution in existing hybrid fuzzers**. This is a speedup of the *analysis component*, not the target. — [arXiv:2412.15931](https://arxiv.org/abs/2412.15931)

**[2023–2024]**

- **ChatAFL: Large Language Model guided Protocol Fuzzing** — Ruijie Meng, Martin Mitáš, Abhik Roychoudhury et al. **NDSS 2024**. **HIGH-CONF/VERIFIED-ish** (author-hosted proceedings PDF named `NDSS24-chatafl.pdf`; repo labelled "(NDSS'24)"). Built on AFLNet; LLM constructs per-message-type grammars, mutates messages, and predicts next messages in a sequence. Reported: **+47.6% / +42.7% state transitions, +29.6% / +25.8% states, +5.8% / +6.7% code coverage** vs. AFLNet and NSFuzz respectively. — [PDF](https://mboehme.github.io/paper/NDSS24-chatafl.pdf); [GitHub](https://github.com/ChatAFLndss/ChatAFL)
- **ChatFuzz: Augmenting Greybox Fuzzing with Generative AI** — arXiv:2306.06782 (Jun 2023). **arXiv-only (NOT PEER-REVIEWED)** as far as this search found. LLM used as a **mutation operator**: picks a seed from the pool and prompts ChatGPT for format-conforming variations. Reported: **+12.77% edge coverage over AFL++** on 12 targets from three benchmarks. — [arXiv:2306.06782](https://arxiv.org/html/2306.06782)
- **FuzzCoder: Byte-level Fuzzing Test via Large Language Model** — arXiv:2409.01944 (Sep 2024). Fine-tuned model predicts byte-level mutation positions/strategies. — [arXiv:2409.01944](https://arxiv.org/pdf/2409.01944)
- **CovRL** (coverage-guided RL fine-tuning for mutation) — cited by the agentic-fuzzing survey as part of the LLM-assisted fuzzing lineage. — [Agentic Fuzzing, arXiv:2605.10074](https://arxiv.org/html/2605.10074)

### Inferences
- The field has converged on a design rule: **keep the LLM out of the hot loop.** Every system either calls the LLM offline, on stagnation, or to emit a *program* (generator/mutator/predicate) that then runs at native speed. This is an argument the user's project can build on directly: the community already treats target-side execution rate as a hard constraint to be worked around, and nobody has tried relaxing the constraint itself.
- **Locus is the single closest published system to "LLM modifies the target"** — it does compile-validated source-level insertion of predicates into the SUT — but its objective is reachability/state relaxation, and its "speedup" is time-to-target-hit, not exec/s. This distinction must be drawn explicitly in the related-work section, because a careless reader will conflate them.

### Gaps
- No paper found that reports exec/s before and after an LLM intervention on the *target*. The exec/s numbers in this literature are always reported to justify *not* calling the LLM often.

---

## Key Question 4: Automated patching and triage around fuzzing

### Takeaway
This cluster is the most peer-reviewed of all the LLM-fuzzing areas (ICSE 2026 SEIP, plus Meta and Google industrial deployments) and it is where **ARVO is the standard dataset**. The task is always *given a crash, produce a patch*; the fuzzer is an oracle, never an optimization target.

### Cited Findings

**[RECENT: 2025–2026]**

- **Fixing Security Vulnerabilities with Agentic AI in OSS-Fuzz** — Yuntong Zhang, Jiawei Wang, Dominic Berzin, Martin Mitáš, Xiaofei Xie, Abhik Roychoudhury (extended/renamed version of arXiv:2411.03346 "Fixing Security Vulnerabilities with AI in OSS-Fuzz"). **ICSE 2026, Software Engineering in Practice (SEIP) track**, DOI **10.1145/3786583.3786880**. **VERIFIED** ([ACM DOI](https://doi.org/10.1145/3786583.3786880); [ICSE 2026 program page](https://conf.researchr.org/details/icse-2026/icse-2026-software-engineering-in-practice/27/Fixing-Security-Vulnerabilities-with-Agentic-AI-in-OSS-Fuzz); [author PDF](https://abhikrc.com/pdf/icse2026-seip.pdf)).
  - System: **CodeRover-S**, an LLM agent for security repair built on **AutoCodeRover**, which consumes the **fuzzer-generated exploit input** and uses it for candidate-patch validation inside the agent loop.
  - Results: plausible patches for **61%–72% of historical OSS-Fuzz vulnerabilities**; in real-world deployment, **plausible patches for 73.3% of unpatched vulnerabilities**; "repaired over half of the tested vulnerabilities." Described as the first study of LLM-assisted security patching on OSS-Fuzz. — [arXiv:2411.03346](https://arxiv.org/abs/2411.03346); [Google blog: From Finding to Fixing](https://blog.google/security/from-finding-to-fixing-reducing-maintainer-burden-with-automated-patches/)
- **AutoPatchBench** (Meta) — announced 2025-04-29 on the Meta engineering blog. Benchmark of real-world C/C++ vulnerabilities with verified fixes **sourced from the ARVO dataset**, adding verification of AI patches through **fuzzing plus white-box differential testing**. ARVO itself is described as **>5,000 reproducible vulnerabilities across >250 OSS-Fuzz C/C++ projects, each with a triggering input and a canonical developer patch**. **Industry blog + benchmark release; not a peer-reviewed paper.** — [Meta Engineering](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/)
- **PatchBench: Evaluating AI Agents for Vulnerability Patching** — arXiv:2609.04075 (Sep 2026). **arXiv-only (NOT PEER-REVIEWED)**. — [arXiv:2609.04075](https://arxiv.org/pdf/2609.04075)
- **AgenticRepair: Multi-Faceted Program Context Engineering for Agentic Vulnerability Repair** — arXiv:2607.29422 (Jul 2026). **arXiv-only**. Contains a useful comparative critique: CyberGym "relies on fuzz-generated inputs that begin execution from artificial fuzz targets rather than real program interfaces," and ARVO "assembles thousands of OSS-Fuzz cases but triggers vulnerabilities through fuzz harnesses that do not reflect how users naturally interact with the software." — [arXiv:2607.29422](https://arxiv.org/pdf/2607.29422)
- **Semantic-aware and Self-improving Program Reduction via Agentic Large Language Models** — arXiv:2607.03766 (Jul 2026). Agentic test-case reduction (a triage-side task); 90 benchmarks, three languages. **arXiv-only**. — [arXiv:2607.03766](https://arxiv.org/pdf/2607.03766)
- **FuzzerAid: Grouping Fuzzed Crashes Based On Fault Signatures** — arXiv:2209.01244 (crash dedup/triage; predates the LLM wave but is the triage baseline). — [arXiv:2209.01244](https://arxiv.org/pdf/2209.01244)

**[2023–2024]**

- **Fixing Security Vulnerabilities with AI in OSS-Fuzz** — arXiv:2411.03346 (Nov 2024), the preprint that became the ICSE 2026 SEIP paper. — [arXiv:2411.03346](https://arxiv.org/html/2411.03346v1)

### Inferences
- **ARVO's canonical role in the literature is as a *patching/reproduction* benchmark** (AutoPatchBench, CyberGym, CyberGym-E2E), never as a fuzzing-efficiency benchmark. Using ARVO for **time-to-bug under a rewritten target** is a genuinely new use of that dataset and should be framed as such.
- The AgenticRepair critique of ARVO/CyberGym (harness-mediated triggering doesn't reflect real user interfaces) is a *criticism of realism* that does not apply to a throughput project — for throughput work, the harness-mediated setting is exactly the setting of interest. Worth pre-empting as a reviewer objection either way.

### Gaps
- Whether CodeRover-S or AutoPatchBench ever measure patch *performance impact* (i.e., does the patch slow the target) was not established; no evidence found that they do.

---

## Key Question 5: DARPA AIxCC — competing Cyber Reasoning Systems, results, papers, OSS-CRS

### Takeaway
AIxCC finals (Aug 2025, DEF CON 33) produced the largest published corpus of agentic vulnerability-discovery engineering, and there is now a USENIX Security 2026 SoK plus per-team system papers. **Explicitly: no finalist CRS optimized target-program performance or fuzzing throughput** — the throughput concerns that appear in the SoK are about *scheduling/timeouts/compute budget*, not about making targets execute faster.

### Cited Findings

**[RECENT: 2025–2026]**

- **SoK: DARPA's AI Cyber Challenge (AIxCC): Competition Design, Architectures, and Lessons Learned** — Cen Zhang, Younggi Park, Fabian Fleischer, Yu-Fu Fu, Jiho Kim, Dongkwan Kim, Youngjoon Kim, Qingxiao Xu, Andrew Chin, Ze Sheng, Hanqing Zhao, Michael Pelican, David J. Musliner, Jeff Huang, Jon Silliman, Mikel Mcdaniel, Jefferson Casavant, Isaac Goldthwaite, Nicholas Vidovich, Matthew Lehman, Taesoo Kim. **arXiv:2602.07666; the arXiv record states USENIX Security 2026** (submitted 2026-02-07, final 2026-08-02); a USENIX-format proceedings PDF is hosted at gts3.org. **VERIFIED (arXiv record + proceedings-format PDF); flag as "USENIX Security 2026" and re-check the official USENIX program page before final citation.** — [arXiv:2602.07666](https://arxiv.org/abs/2602.07666); [HTML v2](https://arxiv.org/html/2602.07666v2); [proceedings PDF](https://gts3.org/assets/papers/2026/zhang:aixcc-sok.pdf)
- **Finalist CRSs (7 teams)** per the SoK: **Atlantis** (Team Atlanta) — ensemble-first architecture of multiple independent bug-finding modules; **Buttercup** (Trail of Bits) — expertise-driven decomposition with deterministic workflows; **RoboDuck** (Theori) — agentic design centered on bug candidates; **Artiphishell** (Shellphish) — comprehensive coverage with 53 components; **FuzzingBrain** (team "All You Need Is A Fuzzing Brain") — simple architecture with 23 diverse LLM strategies; **BugBuster** (42-b3yond-6ug) — pragmatic, favoring fuzzing and program analysis; **Lacrosse** (Lacrosse) — DSPy-based multi-LLM workflow with a Lisp task distributor. — [SoK HTML](https://arxiv.org/html/2602.07666v2)
  - **Correction/caution:** an automated read of the SoK attributed *both* FuzzingBrain and Artiphishell to Shellphish. That is wrong. **FuzzingBrain is the Texas A&M–led team "All You Need Is A Fuzzing Brain" (Jeff Huang), which placed 4th**; Shellphish's CRS is Artiphishell. — [TAMU CSE announcement](https://success.cse.tamu.edu/2025/09/10/texas-am-team-led-by-jeff-won-the-4th-place-in-darpa-aixcc-competition/); [fuzzingbrain.github.io](https://fuzzingbrain.github.io/)
- **Competition design** per the SoK: **48 challenges (16 full-scan, 32 delta-scan) across 24 repositories containing 63 vulnerabilities spanning 34 CWE types, in C and Java**; scoring = PoV (1–2 pts) + Patch (3–6 pts) + SARIF assessment (0.5–1 pt) + Bundle linking (−7 to +7), with time decay and non-linear accuracy multipliers; each team received **$85,000 Azure compute + $50,000 LLM API credits**; **~143 hours of fully autonomous operation**. — [SoK HTML](https://arxiv.org/html/2602.07666v2)
- **Final scores** per the SoK: **Atlantis 392.8; Buttercup 219.4; RoboDuck 210.7**; remaining teams from 153.7 down to 9.6. Official placement: 1st Team Atlanta, 2nd Trail of Bits, 3rd Theori. — [SoK HTML](https://arxiv.org/html/2602.07666v2); [aicyberchallenge.com finals winners](https://aicyberchallenge.com/finals-winners-announcement/); [Trail of Bits blog](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)
- **CONFLICTING VULNERABILITY COUNTS — flag this.** DARPA's official page reports: **54 unique synthetic vulnerabilities discovered** across the final competition's 63 challenges, **43 patched**, plus **18 real non-synthetic vulnerabilities** responsibly disclosed (6 in C, 12 in Java); **53 challenge projects** analyzed over ~143 hours by 7 finalists. The SoK instead reports **22 PoVs exceeding parallel-fuzzing capability** and **25 distinct 0-days discovered, 12 (48%) patched**. These are different countings (synthetic vs. real; DARPA-confirmed vs. SoK-analyzed) and should not be merged. — [DARPA AIxCC results](https://www.darpa.mil/news/2025/aixcc-results) vs. [SoK](https://arxiv.org/html/2602.07666v2)
- **Four of the seven finalist CRSs were open-sourced.** — [DARPA AIxCC results](https://www.darpa.mil/news/2025/aixcc-results); [Trail of Bits Buttercup](https://trailofbits.com/buttercup/)
- **ATLANTIS: AI-driven Threat Localization, Analysis, and Triage Intelligence System** — Team Atlanta's system paper, arXiv:2509.14589 (Sep 2025). **arXiv-only at time of search (NOT PEER-REVIEWED)** — check for a later venue. — [arXiv:2509.14589](https://arxiv.org/pdf/2509.14589)
- **All You Need Is A Fuzzing Brain: An LLM-Powered System for Automated Vulnerability Detection and Patching** — Ze Sheng, Jeff Huang et al. (Texas A&M), arXiv:2509.07225 (Sep 2025). **arXiv-only**. The 4th-place CRS; reported **28 security vulnerabilities discovered incl. 6 0-days in real-world open-source C and Java projects, 14 patched**; described as the most AI-forward finalist (~90% of their codebase AI-written). — [arXiv:2509.07225](https://arxiv.org/html/2509.07225); [TAMU](https://success.cse.tamu.edu/2025/09/10/texas-am-team-led-by-jeff-won-the-4th-place-in-darpa-aixcc-competition/)
- **FuzzingBrain V2: A Multi-Agent LLM System for Automated Vulnerability Discovery and Reproduction** — arXiv:2605.21779 (May 2026). **arXiv-only**. — [arXiv:2605.21779](https://arxiv.org/pdf/2605.21779)
- **OSS-CRS: Liberating AIxCC Cyber Reasoning Systems for Real-World Open-Source Security** — Andrew Chin et al. (Georgia Tech / Taesoo Kim group), arXiv:2603.08566 (Mar 2026); author page lists it under 2026 publications. **Venue UNVERIFIED — treat as arXiv preprint unless confirmed.** — [arXiv:2603.08566](https://arxiv.org/pdf/2603.08566); [taesoo.kim PDF](https://taesoo.kim/pubs/2026/chin:oss-crs.pdf)
  - OSS-CRS is now an **OpenSSF project**: an open framework/CLI + compose interface for orchestrating bug-finding fuzzers, LLM bug-fixing agents, triage systems, and **seed generators** against OSS-Fuzz-format targets, with a component registry and the ability to compose multiple CRSs in one campaign. **It adopts the OSS-Fuzz project format as its target interface, so integrated CRSs can target 1,000+ OSS-Fuzz projects without per-project customization.** Validation: porting Atlantis to OSS-CRS found **10 previously unknown bugs (3 high severity) across 8 OSS-Fuzz projects**. — [oss-crs.openssf.org](https://oss-crs.openssf.org/); [ossf/oss-crs GitHub](https://github.com/ossf/oss-crs); [OpenSSF project page](https://openssf.org/projects/oss-crs/)
- **AIxCC finals: Tale of the tape** — Trail of Bits pre-results technical comparison of finalist architectures. **Industry blog.** — [Trail of Bits](https://blog.trailofbits.com/2025/08/07/aixcc-finals-tale-of-the-tape/)

### Did any CRS optimize target performance? — NO
- A directed read of the SoK for throughput/speed/target-modification found **no evidence of any CRS optimizing fuzzing throughput through target-program modification or execution-speed enhancement beyond standard configurations**. The nearest thing is a *deployment-time configuration trade-off* discussion: e.g., a Wireshark CPV was locally patchable by one Atlantis agent, but Atlantis's **30-minute per-CPV timeout — necessary to manage dozens of concurrent challenges — was largely consumed by the Wireshark build alone**. That is build-time/scheduling cost, not target execution rate. — [SoK HTML v2](https://arxiv.org/html/2602.07666v2)

### Inferences
- The AIxCC record is strong negative evidence for the user's critical question at the *systems-engineering* level: seven of the best-resourced agentic security teams in the world, with $135k of compute/LLM budget each and 143 hours of autonomous operation, **spent their LLM budget on PoV synthesis, patching, and triage — and treated per-target execution speed as a fixed constraint to schedule around** (timeouts, concurrency, build cost), not as something an agent could improve.
- OSS-CRS is the natural deployment vehicle for a throughput-optimizing component: it is explicitly a registry of pluggable OSS-Fuzz-format components (fuzzers, seed generators, patchers, triagers) — and the registry's component taxonomy contains **no "target optimizer" category**, which is itself a citable gap.

### Gaps
- Per-team scores for Artiphishell, FuzzingBrain, BugBuster, and Lacrosse were given only as a range (153.7 → 9.6); exact per-team values were not extracted.
- Theori's RoboDuck and 42-b3yond-6ug's BugBuster do not appear to have standalone system papers in these results; only Atlantis, FuzzingBrain, and Buttercup (via Trail of Bits blog/repo) were found.
- Whether the SoK's "22 PoVs exceeding parallel fuzzing capabilities" claim involves any throughput measurement of the fuzzers was not determined.

---

## Key Question 6: Agentic security benchmarks built on OSS-Fuzz/ARVO — venue and exact task definition

### Takeaway
Four to six benchmarks now sit on OSS-Fuzz/ARVO; two are peer-reviewed at ICLR 2026, one reportedly at NeurIPS 2025, the rest are preprints. **Every one of them defines the task as "produce a crashing input and/or a patch" — none defines a task about fuzzing efficiency, throughput, or time-to-bug under a compute budget.**

### Cited Findings

**[RECENT: 2025–2026]**

- **CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale** — arXiv:2506.02548. **ICLR 2026, Oral.** **VERIFIED** ([ICLR 2026 virtual site, Oral](https://iclr.cc/virtual/2026/oral/10011728)).
  - **Task definition:** built on the **ARVO** infrastructure (OSS-Fuzz vulnerabilities packaged as reproducible Docker images). **1,507 unique vulnerabilities across 188 software projects.** Agent is given a (masked) codebase and a fuzz harness and must **generate a PoC input that reproduces the vulnerability** through that harness (vulnerability reproduction / PoC generation). — [arXiv:2506.02548](https://arxiv.org/pdf/2506.02548); [alphaXiv](https://www.alphaxiv.org/abs/2506.02548)
- **CyberGym-E2E: Scalable Real-World Benchmark for AI Agents' End-to-End Cybersecurity Capabilities** — Tianneng Shi, Robin Rheem, Dongwei Jiang, Mona Wang, + ~11 collaborators (UC Berkeley, Johns Hopkins, UC Santa Cruz, UC Santa Barbara), arXiv:2606.04460. **ICLR 2026** (poster). **VERIFIED via [ICLR 2026 virtual page](https://iclr.cc/virtual/2026/10016248)**. *Note a conflict:* one search summary described it as ICML; the ICLR virtual URL is the primary evidence — **cite ICLR 2026**.
  - **Task definition:** extends CyberGym from detection+PoC to the **complete lifecycle: discovery → PoC → patch**, evaluated sequentially on the same vulnerability. **920 real-world vulnerabilities across 139 open-source projects**, from OSS-Fuzz history via **ARVO** Docker containers. Two settings: **patch-only** (agent receives PoC + crash logs) and **end-to-end** (agent must discover the vulnerability itself).
  - **Metrics:** four cumulative validation stages — **S1** PoC triggers crash; **S2** patch eliminates crash from the generated PoC; **S3** existing developer tests still pass post-patch; **S4** patch eliminates crash from the ground-truth PoC.
  - **Baselines/results:** on an initial 615 tasks with a **$10 budget and 90-minute limit** — patch-only / end-to-end (S3): Claude Opus 4.5 **82.3% / 19.2%**; GPT-5.2-Codex **58.5% / 20.7%**; Gemini 3 Pro **77.6% / 22.6%**. Expanded 920-task results: Opus 4.6 **37.9%**, GPT-5.4 **65.9%** (the report writer should re-check which column these expanded numbers belong to).
  - Compared against SEC-bench, SeCodePLT, BountyBench, AutoPatchBench, SecureAgentBench. — [arXiv:2606.04460 HTML](https://arxiv.org/html/2606.04460v2)
- **SEC-bench: Automated Benchmarking of LLM Agents on Real-World Software Security Tasks** — Hwiwon Lee, Ziqi Zhang, Hanxiao Lu, Lingming Zhang, arXiv:2506.11791. Reported as **NeurIPS 2025**. **UNVERIFIED** — this venue came from a search-result synthesis; **confirm on OpenReview/NeurIPS proceedings before citing.**
  - **Task definition:** two tasks — **PoC generation** and **vulnerability patching** — on data drawn from **OSS-Fuzz**. Distinguishing design: **reproduces vulnerabilities in native builds with real program entry points**, provides **human-readable PoCs**, and uses **sanitizer-based oracles for deterministic verification** (explicitly positioned against ARVO/CyberGym's harness-mediated triggering). — [arXiv:2506.11791](https://arxiv.org/pdf/2506.11791)
- **SEC-bench Pro: Can Language Models Solve Long-Horizon Software Security Tasks?** — arXiv:2605.26548 (May 2026). Successor; **arXiv-only**. — [arXiv:2605.26548](https://arxiv.org/pdf/2605.26548)
- **ExploitBench: A Capability Ladder Benchmark for LLM Cybersecurity Agents** — Seunghyun Lee, David Brumley (Carnegie Mellon University + Bugcrowd), arXiv:2605.14153, posted 2026-05-15. **arXiv-only (NOT PEER-REVIEWED)**.
  - **Task definition:** treats exploitation as a **ladder of progressively acquired capabilities** rather than binary success. Decomposes exploitation into **16 measurable flags** spanning coverage → crash → sandbox primitives → arbitrary read/write → control-flow hijack → arbitrary code execution. Each capability verified by a **deterministic oracle** using per-run randomized challenge-response for primitives, **differential execution against ground-truth binaries**, and a signal-handler proof for code execution. Instantiated on **41 V8 bugs**, driving the same JS/WebAssembly attack surface in the real configuration. — [arXiv:2605.14153](https://arxiv.org/abs/2605.14153); [HTML](https://arxiv.org/html/2605.14153v1)
- **FuzzingBrain-Bench V1: Evaluating Open-Ended Bug Discovery by LLMs** — arXiv:2608.25158 (Aug 2026). **arXiv-only (NOT PEER-REVIEWED)**.
  - **Task definition:** the model is given an open-source project plus a **sanitizer-instrumented harness in a self-contained Docker image** and must **generate inputs that trigger as many *distinct* crashes as possible** through that harness — deliberately *open-ended*, unlike PoC-for-a-specified-CVE benchmarks, so that valid crashes not matching a predefined target still count.
  - **Composition:** **77 challenges from 43 open-source projects** — 36 C, 32 C++, 9 Java/JVM.
  - **Scoring:** per-challenge score = number of distinct crash signatures, capped at a per-challenge maximum and weighted by a difficulty coefficient; total out of **579**.
  - **Baseline result:** Claude Opus 4.8 best — crashes in **60 of 77** challenges, score **196/579**. — [arXiv:2608.25158](https://arxiv.org/abs/2608.25158); [GitHub](https://github.com/fuzzingbrain/FuzzingBrain-Bench)
- **AutoPatchBench** (Meta, ARVO-derived) — see Key Question 4. Task: given an ARVO crash + repo, produce a patch; verified by fuzzing + white-box differential testing. — [Meta Engineering](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/)
- **Adjacent/other agentic security benchmarks surfaced (all arXiv-only unless noted):** SecureAgentBench, SeCodePLT, BountyBench (cited by CyberGym-E2E); **AgentCyberRange** arXiv:2606.14295; **SecRespond** arXiv:2607.26791; **Beyond End-to-End Success: Diagnosing Failures in Long-Horizon Security LLM Agents** arXiv:2608.20563; **LLM Agents for Automated Web Vulnerability Reproduction: Are We There Yet?** arXiv:2510.14700.

### Inferences
- The benchmark landscape is saturated on *"can an agent find/reproduce/patch this specific bug?"* and completely empty on *"can an agent make a fuzzing campaign more efficient?"*. A **time-to-bug-on-ARVO-under-fixed-compute** evaluation is therefore a new benchmark formulation, not just a new method — and FuzzingBrain-Bench's "distinct crashes within a budget" scoring is the closest precedent for budget-aware scoring.
- Because CyberGym, CyberGym-E2E, and AutoPatchBench all sit on ARVO Docker images, a throughput project reusing ARVO inherits a well-accepted infrastructure and can cite three ICLR/industry benchmarks as validation of the substrate.

### Gaps
- SEC-bench's venue (NeurIPS 2025, and whether main track or Datasets & Benchmarks) is **UNVERIFIED**.
- The exact number/identity of "CyberGym-E2E expanded 920-task" results per setting was ambiguous in the fetched summary.
- No benchmark found that scores agents on fuzzing throughput, exec/s, or coverage-per-CPU-hour.

---

## Key Question 7 (CRITICAL): Is there ANY published work in which an LLM or agent modifies a target program to make FUZZING FASTER or more efficient?

### Takeaway
**NO.** Across ~23 searches and direct reads of the AIxCC SoK, the 2026 "Agentic Fuzzing" position paper, and the major benchmark papers, **I found no published work — peer-reviewed or preprint — in which an LLM or agent modifies the source of a target program in order to raise fuzzing throughput (executions/second) or reduce per-execution cost.** The two relevant literatures exist and are both active, but they have not been joined: (a) LLM/agentic *code performance optimization*, and (b) *non-LLM* systems work on fuzzing throughput. The user's framing — "nobody applies an LLM to the SPEED of the target" — is supported by this search.

### Search terms used (evidence of aggressive search)
`LLM agent optimize fuzzing throughput executions per second` · `LLM rewrite program source code faster fuzzing execution speed` · `LLM agent source code performance optimization increase fuzzer executions per second ARVO time-to-bug` · `"fuzzing throughput" LLM optimize target program speed 2026` · `agent improves fuzzing efficiency by removing bottlenecks in harness target` · `"make fuzzing faster" LLM agent rewrite target code speedup experiments` · `LLM agent program transformation reduce execution time fuzzing campaign bug discovery rate` · `"fuzz driver" OR "fuzz target" performance tuning LLM "executions/sec"` · `speeding up fuzz targets throughput source modification sanitizer overhead reduction` · `LLM agent makes program run faster benchmark code performance optimization` — plus targeted full-text interrogation of the AIxCC SoK (arXiv:2602.07666) and the Agentic Fuzzing survey (arXiv:2605.10074) specifically asking for throughput/target-speed content.

### Cited Findings — negative evidence

- **Agentic Fuzzing: Opportunities and Challenges** — J. Park & I. Yun, **arXiv:2605.10074 (2026), arXiv-only (NOT PEER-REVIEWED)**. A 2026 position/survey paper that enumerates how agents are applied to fuzzing: **input generation, reasoning engine, pattern matching/variant analysis, harness engineering, seed scheduling**. A directed read for throughput content found: **"The paper makes no mention of using LLMs/agents to optimize target program execution speed or fuzzing throughput. No quotes address rewriting target source code for performance."** Its only runtime discussion is cost management (soft/hard timeouts, a 300-second per-execution timeout for PoC testing, and a budget constraint limiting evaluation to 23.8% of the seed corpus). Its listed open problems are cost-effectiveness, reference-bug availability, design uncertainty, and statistical confidence — **not throughput**. — [arXiv:2605.10074](https://arxiv.org/html/2605.10074)
- **AIxCC SoK (USENIX Security 2026)** — directed read found **no evidence of any of the seven finalist CRSs optimizing fuzzing throughput via target-program modification, harness changes for speed, or execution-speed enhancement beyond standard configuration**; the only speed-adjacent content is scheduling/timeout/build-cost trade-offs. — [arXiv:2602.07666 HTML v2](https://arxiv.org/html/2602.07666v2)
- **The field's stated position is the opposite direction — throughput is a constraint to route around, not to improve:** "Inserting a single 100 ms LLM call per mutation drops throughput by three orders of magnitude." Mitigations are all LLM-side (offline separation, parallelism, stagnation-triggered invocation). — [FuzzPilot, arXiv:2605.26539](https://arxiv.org/pdf/2605.26539)

### Cited Findings — nearest neighbours (and why each is NOT the same thing)

1. **Locus: Agentic Predicate Synthesis for Directed Fuzzing** — **ICSE 2026**, DOI 10.1145/3744916.3773102. *This is the closest published system: an LLM agent emits source-level predicates that are compiled into the target.* But the objective is **reachability** (relaxing target states so directed fuzzers hit them), and the reported **70.3× average / 214.2× max speedup** is **time-to-target-hit, not executions/second**. Modifying the target *for signal*, not *for speed*. — [ACM DL](https://dl.acm.org/doi/10.1145/3744916.3773102); [arXiv:2508.21302](https://arxiv.org/pdf/2508.21302)
2. **HGFuzzer / Directed Greybox Fuzzing via LLM** — arXiv:2505.03425, **arXiv-only**. LLM writes a path-fixing harness *and a custom mutator*; **≥24.8× speedup** — again time-to-bug via better inputs and a narrower harness, not faster target execution. — [arXiv:2505.03425](https://arxiv.org/pdf/2505.03425)
3. **SeedSmith** — **11.51×–14.66× geomean crash-time speedup on Magma** from better *seeds*; explicitly a front-end that leaves the fuzzer and target untouched. — [arXiv:2607.08949](https://arxiv.org/abs/2607.08949)
4. **ELFuzz (USENIX Sec 2025)** — LLM synthesizes a *generation-based fuzzer* so that generation runs at native speed; the efficiency gain is in the generator, not the SUT. — [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/chen-chuyang)
5. **HyllFuzz (arXiv:2412.15931)** — LLM replaces the concolic solver, **3–19× faster than concolic execution in existing hybrid fuzzers**. Speeds up the *analysis engine*, not the target. — [arXiv:2412.15931](https://arxiv.org/abs/2412.15931)
6. **State-Aware Fuzzing of JS Engines with LLM-Guided Instrumentation** (arXiv:2609.24550) — LLM decides where to *instrument* the target; instrumentation **adds** cost for feedback quality. Opposite sign. — [arXiv:2609.24550](https://arxiv.org/html/2609.24550)
7. **Beyond Reproduction: Uncovering Latent Performance Regressions with LLM-Guided Fuzzing (WIP)** — **ICPE 2026 Companion (17th ACM/SPEC ICPE)**, DOI 10.1145/3777911.3801111. **VERIFIED via DOI.** This is LLM-guided fuzzing **to find performance bugs in a program** — the inverse of using an LLM to remove them for fuzzing's benefit. The only paper found that puts "LLM", "fuzzing", and "performance" in one place, and it points the other way. — [DOI](https://doi.org/10.1145/3777911.3801111)

### Cited Findings — the two unjoined literatures

**(a) LLM/agentic code performance optimization (no fuzzing connection found):**
- **PerfCodeBench: Benchmarking LLMs for System-Level High-Performance Code Optimization** — arXiv:2605.15222 (May 2026), **arXiv-only**. Checks compilation, task correctness, and runtime; covers GPU, CPU/cache, parallel computing, data processing, AI inference. Even the strongest model reaches/surpasses the expert reference on only **61.6%** of comparable tasks. — [arXiv:2605.15222](https://arxiv.org/html/2605.15222v1)
- **PERFOPT-Bench: Evaluating Coding Agents on Software Performance Optimization** — arXiv:2607.07744, **arXiv-only**. — [arXiv:2607.07744](https://arxiv.org/pdf/2607.07744)
- **Rethinking Code Performance Benchmarks for LLMs** — arXiv:2607.07619, **arXiv-only**. Finds that with benchmark-provided test suites **only 6.11%** of "performant" LLM implementations are significantly faster than canonical solutions; proposes a multi-agent framework to generate performance-exposing tests. — [arXiv:2607.07619](https://arxiv.org/abs/2607.07619)
- **FasterPy: An LLM-based Code Execution Efficiency Optimization Framework** — arXiv:2512.22827, **arXiv-only**. — [arXiv:2512.22827](https://arxiv.org/pdf/2512.22827)
- **Agentic Code Optimization via Compiler-LLM Cooperation** — arXiv:2604.04238, **arXiv-only**. — [arXiv:2604.04238](https://arxiv.org/pdf/2604.04238)
- **SWE-Perf** — 140 performance-optimization instances across nine major Python projects; agents must produce correct, speed-improving patches. (Referenced in the above; primary source not fetched — **UNVERIFIED venue**.)
- Practitioner evidence that iterative agentic optimization works: repeated agent passes yielded a cumulative **1.5×–2.0× speedup per frontier-model generation** on hand-optimized Rust. **Blog, not peer-reviewed.** — [minimaxir.com](https://minimaxir.com/2026/09/agentic-iteration/)

**(b) Non-LLM fuzzing-throughput systems work (the target-side literature an LLM has never been applied to):**
- **Full-speed Fuzzing: Reducing Fuzzing Overhead through Coverage-guided Tracing** — Nagy & Hicks, arXiv:1812.11875 (IEEE S&P 2019, **HIGH-CONF**). Overhead reductions of up to **1300% (black-box)** and **70% (white-box)** by executing non-coverage-increasing inputs at native speed. — [arXiv:1812.11875](https://arxiv.org/pdf/1812.11875)
- **FuZZan: Efficient Sanitizer Metadata Design for Fuzzing** — Jeon et al., **USENIX ATC 2020**. **VERIFIED** ([USENIX](https://www.usenix.org/conference/atc20/presentation/jeon)). Redesigns sanitizer metadata structures for fuzzing workloads.
- **SAND: Decoupling Sanitization from Fuzzing for Low Overhead** — arXiv:2402.16497. Runs the main loop on a native binary; reports **2.4× / 2.1× / 20.0×** throughput over AFL++-ASan/UBSan, AFL++-Debloat/UBSan, AFL++-MSan. **Venue UNVERIFIED** (likely ICSE/USENIX — check). — [arXiv:2402.16497](https://arxiv.org/html/2402.16497v2)
- **Zeror: Speed Up Fuzzing with Coverage-sensitive Tracing and Scheduling** — **ASE 2020**. **HIGH-CONF** (author-hosted ASE'20 PDF). Self-modifying tracing that removes visited instrumentation points at runtime. — [PDF](http://wingtecher.com/themes/WingTecherResearch/assets/papers/ase20.pdf)
- **CombiSan: Unifying Software Sanitizers for Comprehensive Fuzzing** — VUSec; PDF named `combisan_sec26.pdf`, so **USENIX Security 2026** is likely but **UNVERIFIED**. — [PDF](https://download.vusec.net/papers/combisan_sec26.pdf)
- **FuzzBox: Blending Fuzzing into Emulation for Binary-Only Embedded Targets** — arXiv:2509.05643. Explicitly measures **throughput in executions of fuzz inputs per second**, achieving **~2× baseline** on three MILS targets. Useful as an example of how exec/s is reported as a primary metric in the systems literature. — [arXiv:2509.05643](https://arxiv.org/pdf/2509.05643)

### Inferences
- **The answer to the critical question is a clean NO, and it can be stated with three independent kinds of evidence:** (i) a 2026 survey of agentic fuzzing whose taxonomy has no throughput/target-optimization category; (ii) the AIxCC SoK, covering seven maximally-resourced CRSs, in which no team touched target speed; (iii) an exhaustive set of keyword searches returning only harness/seed/mutator/patch work plus a *disjoint* LLM-code-performance literature that has never been pointed at a fuzz target.
- The intellectual gap is precisely the **intersection** of two mature literatures: LLM code performance optimization (PerfCodeBench, PERFOPT-Bench, SWE-Perf, FasterPy) and fuzzing-throughput systems work (Full-speed Fuzzing, FuZZan, SAND, Zeror). Both sides measure exactly the right thing — one measures speedup of arbitrary code, the other measures exec/s of fuzzing — and no paper connects them.
- **A distinction the related-work section must make carefully:** several papers report large "speedups" (Locus 70.3×, HGFuzzer 24.8×, SeedSmith 11.5–14.7×). All are **time-to-bug** speedups obtained by improving *where the fuzzer goes*, not *how fast each execution is*. The user's contribution is orthogonal and in principle multiplicative with all of them. Reviewers will otherwise read "speedup" and assume overlap.
- A second useful framing: the existing throughput literature (SAND, FuZZan, Zeror, full-speed fuzzing) achieves its gains **generically, in the fuzzer/runtime/sanitizer layer, one system-design effort at a time**. An LLM agent doing it **per-project, in the target's own source**, is a different mechanism that reaches optimizations no generic runtime trick can (algorithmic and data-structure changes tuned to the tiny inputs fuzzing actually feeds).

### Gaps
- I could not rule out an unpublished/industrial effort (e.g., inside Google's OSS-Fuzz team or a CRS vendor) doing target-speed optimization with an LLM; searches of the OSS-Fuzz blog and Google Security Blog surfaced only harness generation and patching.
- I did not find any paper measuring how much *of* OSS-Fuzz target slowness is attributable to project code vs. sanitizer/instrumentation overhead — a number the user's motivation section would benefit from, and which does not appear to exist in the LLM literature.
- Venue status is unconfirmed for SAND (arXiv:2402.16497), CombiSan, and SWE-Perf; and for several 2026 arXiv preprints listed throughout (they may have been accepted since posting).

---

## Cross-cutting surveys and roadmaps worth citing

- **Towards Reliable LLM-Driven Fuzz Testing: Vision and Road Ahead** — arXiv:2503.00795 (Mar 2025). **arXiv-only**. — [arXiv:2503.00795](https://arxiv.org/pdf/2503.00795)
- **Human in the Loop for Fuzz Testing: Literature Review and the Road Ahead** — arXiv:2603.13411 (Mar 2026). **arXiv-only**. — [arXiv:2603.13411](https://arxiv.org/pdf/2603.13411)
- **Agentic Fuzzing: Opportunities and Challenges** — Park & Yun, arXiv:2605.10074 (2026). **arXiv-only**. The single most useful citation for "here is the taxonomy of agentic fuzzing, and target-speed optimization is not in it." — [arXiv:2605.10074](https://arxiv.org/html/2605.10074)
- **SoK: Where to Fuzz? Assessing Target Selection Methods in Directed Fuzzing** — arXiv:2502.08341 (Feb 2025). — [arXiv:2502.08341](https://arxiv.org/pdf/2502.08341)
- **Security-AI-Papers** reading list (community-maintained index of LLM×security papers, useful for completeness sweeps). — [github.com/Marsman1996/Security-AI-Papers](https://github.com/Marsman1996/Security-AI-Papers)

## Global caveats on verification

- Venues confirmed against a primary source in this session: **Fuzz4All (ICSE 2024, ACM DOI 10.1145/3597503.3639121)**; **ELFuzz (USENIX Security 2025)**; **Locus (ICSE 2026, DOI 10.1145/3744916.3773102)**; **Fixing Security Vulnerabilities with Agentic AI in OSS-Fuzz (ICSE 2026 SEIP, DOI 10.1145/3786583.3786880)**; **LLAMAFUZZ (AST 2026)**; **CyberGym (ICLR 2026 Oral)**; **CyberGym-E2E (ICLR 2026)**; **FuZZan (USENIX ATC 2020)**; **Beyond Reproduction (ICPE 2026 Companion, DOI 10.1145/3777911.3801111)**; **AIxCC SoK (arXiv record states USENIX Security 2026)**.
- Reported-but-not-primary-fetched: **PromptFuzz (CCS 2024)**, **CKGFuzzer (ICSE 2025 Companion)**, **"How Effective Are They?" (ISSTA 2024)**, **ChatAFL (NDSS 2024)**, **TitanFuzz (ISSTA 2023)**, **Zeror (ASE 2020)**, **Full-speed Fuzzing (S&P 2019)**.
- **UNVERIFIED and must be checked before publication: SEC-bench (claimed NeurIPS 2025), SAND, CombiSan, SWE-Perf, OSS-CRS.**
- Everything else listed here is **arXiv-only** at the time of this search — a large fraction of the 2025–2026 LLM-fuzzing literature is preprint-only, which the user should state explicitly in the related-work section.
