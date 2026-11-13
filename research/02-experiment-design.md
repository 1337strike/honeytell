# Experiment design and tool architecture

Draft for approval, 2026-11-13. Decisions already taken: timing reported separately for API
and local backends; one honeypot per code lineage; shell protocol only, Galah dropped.

## 1. Threat model

An attacker has a shell on a Linux host after an SSH login. They want to know whether the
host is real before spending effort or revealing tooling. They can issue commands, measure
wall-clock time, and reach one host they own on the internet. They cannot see the honeypot's
configuration, logs or model.

This is the interactive attacker. Valeros et al. (arXiv:2606.28006) show interactive
sessions are 0.10% of authenticated SSH sessions in the wild. We address that directly: the
interactive attacker is rare and is also the only adversary that justifies putting a
language model behind a shell. Against scanners, Cowrie is already sufficient and far
cheaper. The paper will state this in the threat model rather than leave it to a reviewer.

## 2. Targets

Seven endpoints. Repository HEADs resolved 2026-11-13 and pinned at build time.

| ID | Target | Kind | Why it is in the set |
|---|---|---|---|
| H1 | Beelzebub (mariocandela/beelzebub) | LLM, SSH/HTTP/TCP, Go | The most deployed LLM honeypot, shipped in T-Pot CE. No peer-reviewed evaluation exists. |
| H2 | DECEIVE (splunk/DECEIVE) | LLM, SSH, Python | Vendor-backed, independent code lineage. |
| H3 | shelLM (stratosphereips/shelLM) | LLM, SSH, Python | Stratosphere lineage representative. First LLM shell honeypot, EuroS&PW 2024, most cited. |
| H4 | HoneyGPT (zyw-286/HoneyGPT) | LLM on Cowrie, Python | Peer reviewed in Computer Networks 2026. Hybrid design, so it tests whether a static fast path changes detectability. |
| H5 | allsmog/llm-honeypot | LLM on Cowrie, Python | Its README claims timing jitter and a local fast path specifically to defeat fingerprinting. An already-hardened data point for RQ4. |
| B1 | Cowrie (cowrie/cowrie) | classical, medium interaction | The baseline the whole literature uses. |
| B2 | Ubuntu Server VM | real system | Ground truth negative. Every false positive rate is measured here. |

Two risks to settle during build. H3 and H4 may be hard-wired to the OpenAI API, in which
case the local backend reaches them through an OpenAI-compatible shim. H5 has no paper, so
it enters as an engineering artifact and the paper will say so.

## 3. Backends

Two levels, applied to H1 to H5. B1 and B2 have no backend.

- A, cloud API. One model, held fixed. Needs an API key, which is the one thing this project
  cannot do on your laptop alone.
- L, local open-weight. One quantised model served through Ollama's OpenAI-compatible
  endpoint, so every honeypot sees the same interface.

That gives 5 x 2 + 2 = 12 cells.

Timing results for A and L are reported in separate tables and never pooled. The paper will
say that L latency on an i7-10610U without a GPU is an upper bound set by our hardware and
not a property of the honeypot. This was your decision and it is the honest one.

## 4. Probe suite

Six groups. Five instantiate the detection vector categories from Bridges et al.
(arXiv:2510.25939). The sixth is ours.

| Vector | Probes | Maps to SoK category |
|---|---|---|
| V1 timing | per-command latency, variance, latency against output length, latency after a long context | Outputs and behaviour |
| V2 state | write a file then read it back after N unrelated commands; change a permission then stat it; append then wc -l; create a user then check /etc/passwd | Outputs and behaviour |
| V3 interactive | top, watch, vim, less, tab completion, Ctrl-C handling | Functional limitations |
| V4 side effects | HTTP callback to a host we own, DNS lookup of a name we control, file size and sha256 after dd, PID consistency across ps calls | Functional limitations |
| V5 compound | chained pipelines, deliberate syntax errors, wrong flags, nonexistent binaries, exit code checks | Outputs and behaviour |
| V6 model layer | prompt-injection probes that make the backend disclose its instructions or its nature | new, not in the SoK taxonomy |

V6 is worth defending as a contribution. The SoK treats prompt injection as a vulnerability
of the honeypot to be mitigated. We treat it as a detection channel that exists only because
the honeypot is LLM-powered. Magazov et al. (AI 7(8):287) measure instruction leakage as a
defender-side backend selection metric on their own scaffold. Nobody has used it as an
attacker's probe across honeypot implementations.

Target size: roughly 45 probes. Each probe is a pure function of a transcript, so it is
testable offline against recorded sessions.

## 5. Decision rule

This is the methodological core and the reason our numbers should be trusted where an LLM
judge's are not. Honeyval and AdvancedShelLM both report that their agent judge flags real
systems as honeypots at an uncontrolled rate.

Each probe emits a deterministic feature with a threshold fixed before evaluation. Features
are combined with a sequential probability ratio test. We accumulate a log-likelihood ratio
across probes and stop when it crosses a bound chosen for a target false positive rate of
1%, measured on B2.

Three properties follow. The false positive rate is set by construction rather than
observed after the fact. The verdict arrives after the fewest probes that reach confidence,
which answers RQ3 with no extra machinery. And dropping one vector and re-running the test
gives per-vector attribution for RQ2.

Calibration uses B2 and B1 runs on seeds 1 and 2. Evaluation uses seeds 3 to 7. The split is
fixed in the config file and recorded in the run provenance, so the separation is auditable
rather than asserted.

## 6. Statistics

- Detection rate per target and per vector, with Wilson 95% confidence intervals.
- Timing comparisons against B2 with Cliff's delta, which assumes no normality. Latency
  distributions here are skewed and bounded below, so a t-test would be the wrong tool.
- Binary probe outcomes as risk differences against B2, with confidence intervals.
- Benjamini-Hochberg FDR correction at q = 0.05 across the full probe by target grid. With
  roughly 45 probes and 12 cells, uncorrected p-values would be meaningless.
- Five evaluation seeds minimum, with per-seed spread reported, not just the mean.
- Thresholds and the seed split are written into the config before the evaluation seeds run.

## 7. Runtime on your laptop

Estimated for 45 probes, 5 evaluation seeds, 12 cells.

| Cell group | Probes | Per probe | Total |
|---|---|---|---|
| H1-H5 on backend A | 1125 | 2-4 s | about 1 h |
| H1-H5 on backend L | 1125 | 10-25 s | about 5-6 h |
| B1 Cowrie | 225 | under 0.1 s | minutes |
| B2 real VM | 225 | under 0.1 s | minutes |

Call it 7 hours, so an overnight run. A 3B model instead of 7B roughly halves the local
half.

Targets run one at a time, never in parallel. On 16 GB with Ollama holding a 7B Q4 model in
about 5 GB, parallel containers would fit but CPU contention would corrupt every timing
measurement. Sequential execution is a measurement requirement here, not just a memory one.

## 8. Hardening experiment for RQ4

We implement a small set of mitigations and re-measure. Candidates, each tied to a vector
our results identify as strong:

1. Response delay shaping for V1, drawn from a distribution fitted to real shell latency.
2. A deterministic fast path for common commands, which is what H4 and H5 already do, so we
   get a natural comparison.
3. An external state store for V2, which is the fix AdvancedShelLM adopted.
4. A prompt-injection filter on input and output for V6.

We apply these to whichever target is easiest to patch cleanly, most likely H1 or H3, and
report detectability before and after plus the cost to the defender in latency and tokens.
V3 and V4 we expect to be unfixable by prompting, and saying so with data is a result.

## 9. Ethics

- Every target is deployed by us, on an isolated Docker network with no outbound route
  except to the single egress canary.
- The egress canary is a listener you own. No third-party host is contacted by any probe.
- No scanning, no probing of anything on the internet that is not ours.
- We notify the maintainers of the honeypots we test before publication and offer them the
  findings and the hardening results. For a red-team paper this is both correct and useful
  to reviewers.
- The tool is dual use. The paper will carry a paragraph on that, and the README will state
  the intended use is testing your own deployments.

## 10. Tool architecture

```
honeytell/
  pyproject.toml
  honeytell.toml                 # the one config file
  LICENSE                        # Apache-2.0
  README.md                      # reads like a tool, not a paper
  src/honeytell/
    cli.py                       # honeytell run
    config.py                    # pydantic schema for honeytell.toml
    provenance.py                # records commits, model ids, versions, checksums
    transport/
      ssh.py                     # asyncssh client
      recorder.py                # raw bytes plus monotonic timestamps
    probes/
      base.py                    # Probe: id, vector, run(), evaluate() -> Feature
      timing.py  state.py  interactive.py
      sideeffects.py  compound.py  injection.py
    detector/
      features.py
      calibrate.py               # fit thresholds on B1/B2 calibration seeds
      sprt.py                    # sequential decision rule
    analysis/
      stats.py                   # Wilson, Cliff's delta, BH-FDR
      tables.py                  # CSV writers
      report.py                  # markdown writer
  figures/make_figures.py        # reads CSV only, emits PDF
  targets/
    compose/*.yml                # one per target, pinned
    pin.lock                     # resolved commits and image digests
  tests/                         # pytest
```

Output of one run:

```
out/<run-id>/
  raw/<target>-<backend>-<seed>.jsonl   # every probe, every byte, every timestamp
  features.csv
  verdicts.csv
  provenance.json
  report.md
```

One rule governs the whole design: the tool never computes a number that is not written to
CSV, and the figure script reads only CSV. So every number in the paper traces to a file and
a run id. That is how we keep your no-fabrication rule enforceable rather than aspirational.

Single command:

```
honeytell run --config honeytell.toml
```

Provenance records the honeypot commit, the container image digest, the model identifier and
quantisation, every Python dependency version, the config hash, and a checksum of
features.csv. The report embeds this block, so a table in the paper can be traced to the run
that produced it.

## 11. Build stages

1. Config, provenance, SSH transport, recorder, and the probe base class, with tests. Run
   against B2 only, so we can see a real shell's numbers first.
2. Probe groups V1, V2, V5. These need no special infrastructure.
3. V3 and V4, which need a PTY and the egress canary.
4. V6, plus the detector: calibration and the SPRT.
5. Analysis, report, CSV, figures.
6. Target compose files and pin.lock for all seven targets.

You run each stage on your laptop and send me the output before we move on.

## 12. Venue

Deciding after the results, as you asked. The leaning now:

If RQ4 produces real hardening numbers, the paper does not fit in 6 pages with the stats it
needs, and Computers & Security is the right home. That journal already published DecoyPot,
and Computer Networks published HoneyGPT, so the topic has a proven path there.

If hardening turns out thin, the IEEE 6-page route works, and the EuroS&PW active defence
and deception workshop is where shelLM and VelLMes were both published, which makes the
audience exactly right.

We prepare the IEEEtran build from the start either way, because cutting to 6 pages later is
harder than expanding.

---

# Revision 2: zero cost, fully local (2026-11-13)

Constraint from the author: the tool must cost nothing to run and must run on the laptop.
No paid API anywhere. That removes backend A and changes three things. Two of them make
the design stronger, so this revision supersedes sections 3, 7 and parts of 2 and 9 above.

## R2.1 Backend axis without an API

The backend axis becomes two local open-weight models served by Ollama, varying size within
one family and family at one size:

- L1 qwen2.5:3b-instruct-q4_K_M, about 2 GB resident
- L2 qwen2.5:7b-instruct-q4_K_M, about 4.7 GB resident
- L3 llama3.1:8b-instruct-q4_K_M, optional third arm for a family contrast

L1 against L2 isolates model size. L2 against L3 isolates model family. Two arms are the
default and the third is optional, because each arm multiplies runtime.

Honeypots that expect an OpenAI endpoint point at Ollama's OpenAI-compatible route with a
dummy key. Nothing leaves the laptop and nothing is billed.

What we lose: no claim about frontier-model honeypots. The paper states that as a
limitation. It is a narrower claim, not a broken one, and the SoK recommends small
open-weight models for cost- and privacy-constrained deployments, so the configuration we
can afford is also one the literature asks about.

## R2.2 Timing features that do not depend on the hardware

The earlier worry was that a CPU-only backend inflates latency and makes timing detection
trivial. Disclosing that was the plan. A better fix is to stop using absolute latency.

Absolute latency measures the machine. These features measure the mechanism:

1. Slope of response time against output length. A real shell reads a file and returns it,
   so time barely tracks output size. An LLM generates token by token, so time scales with
   tokens produced. The slope is positive for any generator on any hardware.
2. Coefficient of variation across repeated identical commands. A real shell is nearly
   deterministic in timing. Sampling makes a generator vary.
3. Ratio of time for a command with no output to a command with long output. Near 1 on a
   real shell, far from 1 on a generator.
4. Time to first byte against total time. A real shell starts and finishes together. A
   generator streams, so the gap widens with output length.

Every one of these is a ratio or a slope, so a slower laptop moves the numerator and the
denominator together. That makes the timing vector reportable from one machine without a
hardware caveat, which the absolute-threshold version could never be.

Absolute latency is still recorded in the raw transcripts, and reported as descriptive
context only, never as a detection feature.

## R2.3 Every target in a container, including the control

The real-system control becomes a Docker container running real OpenSSH and a real Ubuntu
userland, instead of a full VM. Commands really execute, state really persists, egress
really happens, so it is a real shell by every property our probes test.

The gain is more than saved memory. The honeypots run in containers too, so running the
control in a container holds containerisation constant across every target. No reviewer can
attribute a detection to container artifacts, because the control has the same artifacts.
With a VM control, that confound would be real and unanswerable.

If time allows we validate a subset of probes against a full VM as a secondary check, and
report any disagreement.

## R2.4 Runtime and resumability

All generation is now local, so runtime goes up. For 45 probes, 7 seeds, 5 honeypots:

| Arm | Sessions | Estimated |
|---|---|---|
| L1 3B | 35 | about 5 h |
| L2 7B | 35 | about 11 h |
| Cowrie and the real container | 14 | minutes |

Roughly 16 hours for two arms. That is too long for one sitting, so resumability stops being
a convenience and becomes a requirement:

- Every completed cell is checkpointed. A rerun skips what is already recorded.
- A single cell can be run alone, so the work splits across evenings.
- Killing the process never loses finished work.

Sequential execution stays mandatory. Nothing else may compete for CPU while timing is
measured, and the ratio features in R2.2 tolerate a slow machine but not a machine whose
speed changes mid-run.

## R2.5 Egress canary, local

The canary is a listener on the lab bridge network, on the laptop. A probe requests a URL
carrying a one-time nonce and we check whether the listener saw that nonce. No internet host
is contacted, so the ethics position gets simpler rather than harder: there is no outbound
traffic at all.
