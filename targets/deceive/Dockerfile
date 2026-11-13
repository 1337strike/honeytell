# DECEIVE has no Dockerfile upstream, so this is ours.
#
# Every LLM provider is imported at module scope in SSH/ssh_server.py, so all
# of the langchain integrations have to be present even though only Ollama is
# used. torch comes from the CPU wheel index: the default index would pull
# several gigabytes of CUDA libraries onto a laptop that has no GPU.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu \
      asyncssh \
      langchain langchain-community langchain-core \
      langchain-openai langchain-ollama langchain-aws langchain-google-genai \
      transformers torch anthropic

WORKDIR /opt/deceive
COPY . /opt/deceive/

WORKDIR /opt/deceive/SSH
RUN cp config.ini.TEMPLATE config.ini \
    && ssh-keygen -q -t ed25519 -f ssh_host_key -N "" \
    && pip freeze > /opt/deceive/pip-freeze.txt

EXPOSE 22

# Provider, model, token budget and port are passed on the command line, which
# the server accepts as overrides, so the upstream template stays untouched.
ENTRYPOINT ["python", "ssh_server.py", "-c", "config.ini", "-P", "22"]
