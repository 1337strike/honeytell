# honeytell

Tells you whether a shell you have logged into is a real machine or a honeypot
with a language model behind it.

It logs in over SSH, issues a few dozen commands, and scores the answers. The
verdict comes with the evidence that produced it, so you can see which signal
gave the target away.

Everything runs locally. There is no API key and nothing is billed.

## What it looks for

Six groups of signals. Three are implemented, three are stubs waiting for the
next release.

| Vector | Status | What it measures |
|---|---|---|
| `timing` | ready | Whether response time grows with the amount of output, how much identical commands vary, how much of a reply arrives after the first byte |
| `state` | ready | Whether a file you wrote is still there after a dozen unrelated commands, whether a line count matches what you appended, whether a mode you set is the mode reported back |
| `compound` | ready | Whether the target can compute a SHA-256 digest, do arithmetic, and produce the error messages and exit codes that coreutils and bash produce |
| `interactive` | stub | `top`, `vim`, `less`, tab completion |
| `sideeffect` | stub | Whether an outbound request actually reaches a listener you control |
| `injection` | stub | Prompt-injection probes that make a model describe itself |

The timing features are ratios and slopes, never absolute latency. Absolute
latency tells you how fast the machine is. A ratio tells you whether something
is generating text, and it means the same thing on a slow laptop and on a fast
server.

The digest probe is the one worth knowing about. It asks for the SHA-256 of a
value generated for that run. A real shell runs `sha256sum`. A language model
has to produce 64 hex characters it cannot compute and has never seen, so it
either invents a digest or declines.

## Install

Needs Python 3.11 or newer.

```bash
git clone https://github.com/1337strike/honeytell
```

```bash
cd honeytell && python3 -m venv .venv && . .venv/bin/activate
```

```bash
pip install -e ".[analysis,figures,dev]"
```

### Setup on Arch Linux

Everything needed is in `extra`. `docker-buildx` is separate from `docker` and
`docker compose build` will not work without it.

```bash
sudo pacman -S --needed docker docker-compose docker-buildx ollama
```

```bash
sudo systemctl enable --now docker ollama
```

```bash
sudo usermod -aG docker "$USER"
```

Log out and back in for the group to take effect, or the Docker commands below
will fail on the socket.

**Stop Ollama unloading models between cells.** Ollama keeps a model in memory
for five minutes after the last request and then drops it. A run is sequential
and takes hours, so a reload will land inside a timed command and inflate it by
however long the model takes to load. That single reading is then a measurement
of your disk, not of the honeypot.

```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
```

```bash
printf '[Service]\nEnvironment="OLLAMA_KEEP_ALIVE=-1"\n' | sudo tee /etc/systemd/system/ollama.service.d/keep-alive.conf
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

A negative value means keep the model loaded indefinitely. Both default
backends resident at once come to roughly 7 GB, which fits in 16 GB alongside
the containers.

**Give the backend enough context.** Ollama sizes the context window from
available VRAM, and on a CPU-only machine that lands at 4096 tokens. A
honeytell session is 82 commands and the honeypot feeds the whole conversation
back on every one of them, which comes to roughly 3,400 to 4,400 tokens once a
honeypot's system prompt is counted. That sits right on the limit, so some
targets would overflow near the end of a session and others would not, for a
reason that belongs to our setup rather than to their design.

```bash
printf '[Service]\nEnvironment="OLLAMA_CONTEXT_LENGTH=8192"\n' | sudo tee /etc/systemd/system/ollama.service.d/context.conf
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

Set `context_length` in `honeytell.toml` to the same number. The server does
not report the value back, so declaring it is the only way it reaches
`provenance.json`.

Headroom here is deliberate. Running out of context is a real way for a
honeypot to fail, and giving every target more than it needs means a detection
cannot be blamed on our budget. The measurement is then conservative: it says a
honeypot was identified even under conditions chosen to favour it.

Pull the models named in the config:

```bash
ollama pull qwen2.5:3b-instruct-q4_K_M && ollama pull qwen2.5:7b-instruct-q4_K_M
```

Arch marks its system Python as externally managed, so `pip install` outside a
virtual environment is refused. The `python3 -m venv` step above is what makes
the install work, not a style preference.

## Usage

Write a starter config:

```bash
honeytell init
```

Check that your machine and your config are in order:

```bash
honeytell doctor --config honeytell.toml
```

This reports whether Docker and Ollama are on your PATH, whether each backend
answers, and whether each target can be logged into. It opens a real session
and runs a command, so it catches wrong credentials rather than only a closed
port. Fix anything it calls out before running. Pass `--no-login` to stop at
the port check.

See the probes and the features each one produces:

```bash
honeytell probes
```

Run the whole thing and write a report:

```bash
honeytell run --config honeytell.toml --extra-real-seeds 40
```

`run` checks every target in the plan first and tells you which are not
listening. Sessions against a target that is down are recorded as unreachable
and left out of the report, because a detection rate of zero for something that
was never running is an artifact rather than a finding. If nothing in the plan
is reachable the run stops instead of spending the night on it.

Run one target while you are still setting the others up:

```bash
honeytell run --config honeytell.toml --target beelzebub --backend qwen7b
```

Re-analyse a finished run without touching the targets again:

```bash
honeytell report --run out/run-abc123456789
```

## Deploying the targets

`targets/README.md` has the full procedure: the lab network, the Ollama bind,
fetching each honeypot at its pinned commit, and building. The short version:

```bash
docker network create --driver bridge --subnet 10.88.0.0/24 --gateway 10.88.0.1 honeytell-lab
```

```bash
./targets/fetch-sources.sh
```

```bash
for t in real cowrie beelzebub deceive; do docker compose -f "targets/$t/compose.yml" up -d --build; done
```

## The real-system control

Detection is meaningless without something known to be real. The repo ships
one:

```bash
docker compose -f targets/real/compose.yml up -d --build
```

It is a container with a real OpenSSH server and a real Ubuntu userland,
listening on `127.0.0.1:2200`. Commands actually execute and state actually
persists.

It runs in a container on purpose. The honeypots run in containers too, so
container artifacts are the same everywhere and cannot be what separates them.

Real sessions cost milliseconds, so run a lot of them. `--extra-real-seeds 40`
costs under a minute and is what makes the threshold meaningful.

## How the verdict is reached

The decision rule is calibrated on the real system and never on a honeypot.

For each feature, honeytell learns the range a real shell produces. Scoring a
session asks how surprising each value would be for a real shell, adds those
surprises up in the order the probes ran, and stops at the first point the total
crosses a threshold.

The threshold is a quantile of that same total measured on real sessions, so
the false alarm rate is whatever you asked for with `--alpha` rather than
whatever happens to come out. The default is 0.01.

Real sessions are split three ways and no number comes from the data that
shaped it:

- first half of the real calibration sessions set the per-feature ranges
- second half set the threshold
- real evaluation sessions report the false alarm rate

Because nothing is fitted on honeypots, adding a target never changes how the
others are judged.

### How many real sessions you need

The score is built from empirical p-values, so its resolution is limited by how
many real sessions you ran. The smallest rate the statistic can express at all
is one over the number of sessions used for the threshold. Asking for
`--alpha 0.01` with 20 real sessions is asking for something the data cannot
say.

honeytell will not pretend otherwise. When the sample is too coarse it puts the
threshold above the largest real score, so nothing real is flagged, and
`report.md` says which rate the sample actually supports and how many sessions
you would need for the one you asked for.

Rule of thumb: you want at least `2/alpha` real sessions, because they are
split in half. For the default alpha of 0.01 that is 200, which is a couple of
minutes against the control container. `--extra-real-seeds 200` is not
excessive.

The reported false alarm rate needs its own sample. It comes from the real
evaluation sessions, and five of them cannot measure a rate of one percent: the
interval runs from 0.04 to 0.62 and says nothing. Use
`--extra-real-eval-seeds 100` so the number means something.

### Order of execution

Sessions inside a target are interleaved rather than run in role order. A
machine warms up: page cache fills, the CPU leaves its idle clock, a container
settles. Running every evaluation session in the opening minutes and every
calibration session over the following hour makes the two sets differ by when
they ran, and the timing features are exactly what such a drift moves. The
order is shuffled from `shuffle_seed`, so it is reproducible from the config
and is recorded in provenance.

Each session also starts with a few throwaway commands that are not recorded,
so the first scored probe is not paying for a cold connection.

## Output

One run directory under `out/`:

```
out/<run-id>/
  raw/<target>-<backend>-seed<n>.jsonl    every command, its output and its timings
  raw/<target>-<backend>-seed<n>.meta.json
  features.csv        one row per scored feature
  steps.csv           one row per command
  verdicts.csv        one row per session, with the per-vector breakdown
  calibration.json    the ranges and the threshold
  provenance.json     versions, pinned commits, config hash, file checksums
  report.md           the tables
```

Every number in `report.md` also exists in a CSV. Nothing is computed that is
not written down.

Runs are resumable. The run id defaults to a hash of your config, so running
the same config again picks up where it stopped. Interrupting it never loses a
finished session.

## Configuration

One file. `honeytell init` writes a commented copy.

Two settings decide what your measurements mean:

`idle_ms` is the silence that marks the end of a reply. It must be longer than
the longest gap between tokens on your slowest model, or replies get cut off
halfway. The default is 1500. If you see truncated output in the transcripts,
raise it. The wait itself is not counted in any timing, because the clock stops
at the last byte that arrived rather than when honeytell gives up waiting.

`calibration_seeds` and `evaluation_seeds` must not overlap. The config refuses
to load if they do.

Every target with a `repo` must pin a `commit`. A result you cannot trace to a
specific version of the thing you tested is not worth much.

## Figures

```bash
python figures/make_figures.py --run out/run-abc123456789
```

Writes PDF and PNG into `<run>/figures`. The script reads only the CSVs, so a
figure cannot disagree with a table.

## Tests

```bash
pytest
```

The probe tests run against two fake shells: one that behaves like a real
machine, and one that behaves like a language model with no filesystem. That
keeps the scoring testable without deploying anything.

## Intended use

Test deployments you run. The tool exists so people building honeypots can find
out what gives theirs away, and fix it.

Point it only at systems you own or have written permission to test.

## License

Apache-2.0.
