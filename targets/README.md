# Deploying the targets

Every target runs in a container on one isolated network, including the real
control. That keeps the network path identical for all of them, so container
and NAT artifacts are a constant and cannot account for a detection.

Ready now: the real control, Cowrie, Beelzebub and DECEIVE. shelLM, HoneyGPT
and the Cowrie fork in `honeytell.toml` do not have deployment files yet;
`honeytell doctor` will report them closed and a run leaves them out.

## 1. Let the backend reach the containers

Ollama listens on 127.0.0.1 by default, which inside a container means the
container itself. The honeypots need to reach the host, so bind it to the
machine rather than to loopback:

```bash
printf '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11434"\n' | sudo tee /etc/systemd/system/ollama.service.d/bind.conf
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

This opens the port to your network, so do it on a machine you control and not
on an untrusted one. To narrow it, bind to the lab gateway alone with
`OLLAMA_HOST=10.88.0.1:11434`, after creating the network below; the `ollama`
command then needs the same value in its environment to find its own server.

## 2. Create the lab network

A fixed subnet, so the gateway address the honeypots use is the same on every
machine and can be written into their configs.

```bash
docker network create --driver bridge --subnet 10.88.0.0/24 --gateway 10.88.0.1 honeytell-lab
```

```bash
docker network inspect honeytell-lab --format '{{(index .IPAM.Config 0).Gateway}}'
```

That must print `10.88.0.1`, which is the address in every honeypot config
here.

## 3. Fetch the honeypot sources at their pinned commits

```bash
./targets/fetch-sources.sh
```

Checkouts land in `targets/<name>/src` and are not tracked by this repo. The
commits are the ones `honeytell.toml` records, so a result can be traced to the
code that produced it.

## 4. Build and start

```bash
docker compose -f targets/real/compose.yml up -d --build
```

```bash
docker compose -f targets/cowrie/compose.yml up -d --build
```

```bash
docker compose -f targets/beelzebub/compose.yml up -d --build
```

```bash
docker compose -f targets/deceive/compose.yml up -d --build
```

DECEIVE takes the longest to build. Every language model provider is imported
at module scope in its server, so all of the langchain integrations have to be
installed even though only Ollama is used, and that pulls in torch. The CPU
wheel index in its Dockerfile keeps that to a few hundred megabytes instead of
several gigabytes of CUDA libraries.

## 5. Check before running anything

```bash
honeytell doctor --config honeytell.toml
```

`doctor` logs in and runs a command, so it reports authentication failures
rather than only whether a port is open. Every target it lists as `ok` is ready;
anything else needs fixing first, because a run against a target that does not
answer produces nothing.

If Cowrie reports an authentication failure, the userdb mount path in its
compose file does not match the pinned commit's layout. Find where that commit
keeps `etc/userdb.txt` and correct the volume.

## Ports

| Target | Backend | Port |
|---|---|---|
| real | none | 2200 |
| cowrie | none | 2201 |
| beelzebub | qwen3b | 2210 |
| beelzebub | qwen7b | 2211 |
| deceive | qwen3b | 2220 |
| deceive | qwen7b | 2221 |
| shellm | qwen3b / qwen7b | 2230 / 2231 |
| honeygpt | qwen3b / qwen7b | 2240 / 2241 |
| llmhoneypot | qwen3b / qwen7b | 2250 / 2251 |

Each honeypot and backend pair is its own container, so nothing can carry over
between two models that are supposed to be compared.

## Stopping

```bash
for t in real cowrie beelzebub deceive; do docker compose -f "targets/$t/compose.yml" down; done
```
