# Literature review and gap statement

Status: draft 1, 2026-11-13. Every entry below was checked against arXiv metadata or the
Crossref API on 2026-11-13. Items marked "unverified" are leads I have not confirmed yet.

## 1. How the field is organised

Three bodies of work touch this project. They have stayed mostly separate, which is where
our opening is.

### 1.1 LLM-powered honeypots, evaluated by their builders

Every system below is evaluated by the team that built it, and the question asked is "how
realistic is my honeypot", not "how fast can an attacker break it".

| Work | System | Evaluation method | Headline number |
|---|---|---|---|
| McKee & Noever 2023, arXiv:2301.03771 | concept | conceptual prompting | none |
| Ragsdale & Boppana 2023, IEEE Access 11:117528-117545 | SSH/Telnet shell | Levenshtein, script replay | none on detection |
| Sladić et al. 2024, shelLM, EuroS&PW, DOI 10.1109/EuroSPW61312.2024.00054 | SSH shell | 12 security researchers | TNR 0.90 |
| Wang et al. 2024, HoneyGPT, arXiv:2406.01882 (unverified id) | SSH/Telnet | script replay, in the wild | 0.58% / 0.048% of connections were real sessions |
| Guan et al. 2024, HoneyLLM, IEEE CNS 2024 pp. 1-9 | SSH/Telnet | script replay, in the wild | session length 2.96 to 5.83 commands; 99.2% scanners |
| Weber et al. 2024, IEEE Access | SSH shell | 5 experts, SBERT | 52% of responses convincing |
| Otal & Canbaz 2024, IEEE CNS 2024 pp. 1-6 | SSH shell | similarity | none on detection |
| Fan et al. 2024, HoneyLLM, ICICS, Springer pp. 253-272 | SSH shell | 7 fidelity metrics | none on detection |
| Johnson et al. 2024, LIMBOSH, IEEE CSR pp. 387-394 | SSH shell | 4 experts vs real server | none on detection |
| Sladić et al. 2025, VelLMes, EuroS&PW, DOI 10.1109/EuroSPW67616.2025.00082 | SSH, MySQL, POP3, HTTP | 89 human attackers | ~30% thought it was real |
| Sezgin & Boyacı 2025, DecoyPot, Computers & Security 154:104458 | web API | engagement | none on detection |
| Jiménez-Román et al. 2025, arXiv:2509.16682 | LDAP | syntax/structure accuracy | none on detection |
| Malhotra 2025, LLMHoney, arXiv:2509.01463 | SSH shell | 13 open-weight LLMs | accuracy, latency, hallucination |
| Magazov et al. 2026, AI 7(8):287, DOI 10.3390/ai7080287 | SSH shell | 42-command battery, 11 backends, 8736 responses | 1 of 11 backends leaked its prompt |
| Magazov et al. 2026, Future Internet 18(7):359, DOI 10.3390/fi18070359 | SSH shell | phase-adaptive routing | fidelity vs latency trade-off |
| Sladić et al. 2026, AdvancedShelLM, arXiv:2606.27990 | SSH shell | unit tests, ARACNE agent, humans, internet | 99.02% unit test pass; beat Cowrie with humans |

Two of these are worth separating out because they come closest to what we want to do.

Magazov et al. (AI 7(8):287) run a fixed 42-command battery across eleven backends on one
scaffold they wrote themselves, scoring instruction leakage, fidelity, hallucination,
latency, verbosity and stability. It is the most quantitative shell-side work that exists.
It compares backends for a defender choosing a model. It does not compare honeypot
implementations, has no real-system control, and produces no detection decision.

Sladić et al. (AdvancedShelLM) use an LLM agent (ARACNE) as the judge of whether the
target is a honeypot. Their own finding is that the agent "had issues making a decision if
the system is honeypot or not, but showed slight bias towards saying honeypot, even for a
real Ubuntu shell." That is a measurement instrument with an uncontrolled false alarm rate.

Beelzebub and Galah are the two most widely deployed open-source LLM honeypots, both
shipped in T-Pot Community Edition. Neither has a peer-reviewed evaluation. The only
primary sources are the author's Hack.lu 2024 and Honeynet 2024 talks.

### 1.2 Honeypot fingerprinting, done against classical honeypots

| Work | Vector | Scale |
|---|---|---|
| Krawetz 2004, IEEE Security & Privacy 2(1):76-79 | egress check (Honeypot Hunter) | in the wild |
| Holz & Raynal 2005, IEEE SMC IAW pp. 29-36 | shell commands, MAC addresses | lab |
| Defibaugh-Chavez et al. 2006, IEEE IAW | service coverage, ICMP timing | lab |
| Fu et al. 2006, IEEE DASC pp. 211-218 | link latency on Honeyd | lab |
| Mukkamala et al. 2007, IEEE SMC IAS pp. 92-98 | ML on timing statistics | lab |
| Wang et al. 2010, IJICS 4(1):30-51 | botnet egress check | lab |
| Vetterl & Clayton 2018, USENIX WOOT | protocol-level probing, SSH/Telnet/HTTP | internet scale |
| Huang et al. 2019, Security and Communication Networks | ML over protocol, flow, system features | internet scale |
| Morishita et al. 2019, pp. 134-143 | 20 response signatures | 19,000+ found |
| Cabral et al. 2019 (CSCI pp. 166-171) and 2021 (IFIP SEC pp. 317-331) | Cowrie artefacts, then hardened config | lab |
| Srinivasa et al. 2021, arXiv:2109.10652 | multistage framework | 2.9B addresses, 21,855 honeypots |
| Chaudhry et al. 2026, Future Internet 18(4):190, DOI 10.3390/fi18040190 | review of techniques and evasion | survey |

Not one of these touches an LLM-powered honeypot. The newest primary measurement here is
from 2021, three years before the first LLM shell honeypot shipped.

### 1.3 The near misses

Four works sit close enough that we have to be precise about the difference.

**Bridges et al., SoK: Honeypots & LLMs, arXiv:2510.25939** (v1 Oct 2025, v4 Apr 2026).
Gives us the taxonomy we should adopt: four detection vector categories, namely contents
and network posture, outputs and behaviour, functional limitations, and synthesis of
multiple features. It runs no experiments of its own. Its roadmap asks for exactly our
kind of work, calling for "a dynamic adversarial research ecosystem, a contained platform
where LLM-powered attackers and honeypots can be pitted against each other". It names
three unsolved simulation problems: dynamic and interactive commands, complex and compound
commands, and outbound network actions. It also says "timing remains a critical and
unresolved challenge" and that no configurable open-source implementation of the canonical
architecture exists, which it calls "a direct engineering gap hindering reproducible
research".

**Vero et al., Honeyval, arXiv:2605.29963** (v1 May 2026, v2 Nov 2026, Google DeepMind and
ETH Zurich). The strongest overlap. It is an evaluation framework for LLM-powered HTTP
honeypots, grounded in 16 backend applications, with AI hacking agents as attackers and
control tasks that measure false alarms on real applications. It reports detection true
positive rates, interaction length, latency and cost. Four differences matter:

1. HTTP REST APIs only. Its own future work says "future work could extend the framework
   beyond HTTP honeypots to honeypots simulating common OS shells".
2. It evaluates a honeypot the authors wrote, because "no prior work provides an
   out-of-the-box implementation for LLM-powered honeypots for custom HTTP REST APIs". No
   deployed open-source honeypot is tested.
3. Detection is the agent self-reporting. Agents are "instructed to alert if they believe
   that they are interacting with a honeypot". For two of their agents they conclude the
   high false positive rate makes the judgement "unreliable".
4. No per-signal attribution. They report "no clear correlation between the honeypots'
   latency or functional fidelity and the detection rates", and the only signal evidence is
   reading agent logs, where agents "repeatedly cite response latency and timeouts".

**Xie et al., arXiv:2609.08093** (Sep 2026). Honeypot-aware budget allocation for LLM
attack agents. Its post-connect detector checks "command availability, output consistency,
filesystem and process information, state persistence, and plausible side effects across
consecutive commands", which is close to our probe list. The honeypot pool is Cowrie,
Wetland, Glastopf, HoneySSH, sshForShits, sshsyrup, sshesame and a second Cowrie config.
All classical. No LLM honeypot appears anywhere in the testbed, and the research question
is target selection under budget, not fingerprinting.

**Nieponice et al., ARACNE, arXiv:2502.18528** (Feb 2025). An LLM shell pentesting agent,
60% success against shelLM. It is an attacker, and it is the judge used by AdvancedShelLM,
but it is not a fingerprinting instrument and reports no detection metrics.

Three more for context. Pasquini et al., LLMmap, USENIX Security 2025 pp. 299-318, active
fingerprinting that identifies which of 42 LLM versions backs an application with 8
queries. It identifies the model, not the deception. Reworr & Volkov, arXiv:2410.13919,
runs the opposite direction, a honeypot using prompt injection and timing to spot LLM
agents. Ilg et al. 2025, Beekeeper, IEEE Access, uses an LLM to critique honeypot realism
as a defender tool, and found that attempted downloads and file use often give honeypots
away. Aradi et al. 2025, Acta Polytechnica Hungarica 22(12), proposes honeypot metrics
including fingerprinting resistance.

### 1.4 One finding that constrains our framing

Valeros et al., arXiv:2606.28006 (Jun 2026), deployed eleven SSH honeypots for fifteen days
and found 99.23% of 177,622 authenticated sessions were non-interactive, with interactive
sessions at 0.10%. Their point is that a honeypot evaluated on session length and command
count can miss most real attacks. We have to address this head on rather than hope nobody
raises it. Our answer: the interactive attacker is the minority case and also the only case
LLM honeypots are built for, since the whole argument for putting a language model behind a
shell is to hold a thinking adversary. We will say so in the threat model and cite this
paper as the reason the scope is narrow.

## 2. Gap statement

Attacker-side detection of LLM-powered honeypots has been discussed, taxonomised and
measured as a side effect, and never measured directly against deployed systems.

What is missing, concretely:

1. No study probes real deployed open-source LLM shell honeypots. Honeyval tests a
   purpose-built HTTP honeypot; the fingerprinting literature stops at classical honeypots;
   Xie et al. use classical honeypots only.
2. Detection is measured by asking an LLM agent for its opinion. Both Honeyval and
   AdvancedShelLM report that this judge has an uncontrolled false alarm rate on real
   systems. Nobody has used a deterministic, reproducible decision rule calibrated against
   a real machine.
3. No per-vector attribution. The SoK says timing is critical and unresolved; Honeyval
   finds no correlation with latency and falls back to reading logs. Which signal actually
   carries the decision is an open question.
4. Cost to a verdict is unreported. Interaction length is measured from the defender's
   side. How many commands and how many seconds an attacker needs to be confident is not.
5. Honeypot design and LLM backend are confounded throughout. Each paper evaluates one
   system on one or more backends. Nobody holds the backend fixed across designs.
6. Hardening advice exists (Cabral et al. for Cowrie) but no equivalent for LLM honeypots,
   and no measured before and after.

## 3. Proposed research questions

RQ1. Can a deterministic probe suite distinguish LLM-powered shell honeypots from a real
Linux system, and at what true positive and false positive rate per honeypot?

RQ2. Which fingerprinting vectors carry the decision, and how much of the detectability is
attributable to honeypot design as opposed to the LLM backend?

RQ3. What does a confident verdict cost the attacker, in commands issued and wall-clock
seconds?

RQ4. Do candidate hardening measures measurably reduce detectability, and what do they cost
the defender?

## 4. Proposed contributions

C1. honeytell, an open-source Apache-2.0 harness that probes a shell endpoint and emits a
verdict with per-vector evidence. Honeypot commits, model identifiers and dependencies are
pinned, so a run is reproducible. One command produces the markdown and CSV that every
table and figure in the paper is generated from. This answers the engineering gap the SoK
names.

C2. The first attacker-side measurement across several deployed open-source LLM shell
honeypots, with Cowrie and a real Linux VM as controls, and the backend held constant where
the honeypot allows it.

C3. Per-vector attribution with effect sizes, confidence intervals and multiple-comparison
correction, which gives honeypot builders a ranked list of what to fix.

C4. Cost-to-verdict curves, turning detectability into something an attacker and a defender
can both reason about.

C5. A hardening evaluation: we implement a subset of the recommendations and measure the
change in detectability and the cost to the defender.

## 5. Open questions for the next step

1. The CPU-only backend problem. On an i7-10610U with no GPU, a local quantised model will
   be slow. That inflates latency and makes the timing vector trivially easy, which is not
   representative of a real deployment on server hardware. Options: report timing separately
   for API and local backends; or normalise against measured single-token latency; or drop
   the local backend from the timing analysis and keep it only for the content vectors.
   This needs a decision before we build.
2. Honeypot lineage. shelLM, VelLMes and AdvancedShelLM are the same research group and
   share code. Counting them as three independent honeypots would overstate our coverage.
3. Galah is HTTP, not a shell. Including it means either two protocols or dropping it.
4. Repositories reachable and HEAD resolved on 2026-11-13:
   - cowrie/cowrie a4237125e8a55493b342dea9e4ede052f9314193
   - mariocandela/beelzebub df6de36a087c867f7cce90a0d125351bd47b3343
   - 0x4D31/galah 8f77b85e892731cf1402963d8121c79fef0e59c7
   - stratosphereips/shelLM a480a5c6e623390786e662c34b6d1ecd8bb98af4
   - splunk/DECEIVE cce98f3dcd9de74f32f683998e95aa19b795724e
   - stratosphereips/VelLMes-AI-Deception-Framework 192fa5084df84b38a16f6581939fd3143c350181
   AdvancedShelLM, Ohra and LLMHoney repositories are not yet located.

## 6. Not yet verified

- Wang et al. 2024 HoneyGPT: I have the SoK's citation but not the arXiv id. Needs checking.
- Guan et al. HoneyLLM and Fan et al. HoneyLLM are different papers with the same name. The
  SoK cites both. Confirm both DOIs before use.
- Honeyval's code URL. Search results showed two candidates. The paper text says it is open
  sourced; I have not read the exact URL from the paper.
- Aradi et al. 2025: title and venue from the SoK reference list only.
- The Galah and Beelzebub talk recordings.

## 7. Additions after verification round 2 (2026-11-13)

Resolved from the "not verified" list:

- Wang et al., HoneyGPT: "HoneyGPT: Breaking the trilemma in honeypots with large language
  models", Computer Networks 282:112223, 2026, DOI 10.1016/j.comnet.2026.112223. Peer
  reviewed, and code is at github.com/zyw-286/HoneyGPT.
- Guan et al., HoneyLLM, IEEE CNS 2024 pp. 1-9, DOI 10.1109/cns62487.2024.10735663.
- Fan et al., HoneyLLM, LNCS pp. 253-272, DOI 10.1007/978-981-97-8801-9_13. Confirmed a
  different paper from Guan et al. despite the shared name.

Found during verification, both defender side, both for the related work table:

- Godburn & Mahalal, "Evaluating Large Language Models for Realistic Real-Time Linux Shell
  Honeypots", Cyber-AI 2026 pp. 624-631, DOI 10.1109/cyber-ai70573.2026.11755241.
- Fan et al., "HoneyLLMd: A Large Language Model-Powered Adaptive Honeypot System", IEEE
  Transactions on Network Science and Engineering 13:8646-8665, 2026,
  DOI 10.1109/tnse.2026.3683862.

Neither changes the gap statement. Both evaluate honeypot realism from the builder's side.

Repository status after round 2. Resolved HEAD on 2026-11-13:

- zyw-286/HoneyGPT 55b3e7396382f8d191d447db9b1b59b02c735d8f
- allsmog/llm-honeypot be2ab62fa6a9489469b0ac248cb9b5c74734961d
- PalisadeResearch/llm-honeypot 156004a1b122f201448635417ee47bd44d7f28ca
- al2al85/HoneyMind db9fc6bc7ec6e62f537c8e481c3cfc9a2fa8de90
- R-mozee/GenShells-Adaptive-Honeypot cbaa0d099b1ae2e227db7816ca0f8e0eed12f240

Not found under the obvious names: AdvancedShelLM, Ohra, LLMHoney. AdvancedShelLM matters
because it is the newest paper in the Stratosphere lineage. If no code exists, the lineage
representative has to be shelLM or VelLMes.

Still unverified: Aradi et al. 2025 (title and venue come from the SoK reference list only),
Honeyval's exact code URL, and the Galah and Beelzebub talk recordings.
