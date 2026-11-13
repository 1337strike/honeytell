# The real-system control.
#
# A real OpenSSH server over a real Ubuntu userland. Commands actually run,
# state actually persists, side effects actually happen. It is a real shell by
# every property the probes test.
#
# It runs in a container for the same reason the honeypots do, which means
# container artifacts are constant across every target and cannot by themselves
# account for a detection.
FROM ubuntu:24.04

ARG USERNAME=analyst
ARG PASSWORD=analyst

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server coreutils procps vim-tiny less curl ca-certificates \
      findutils grep gawk sed bsdmainutils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash "$USERNAME" \
    && echo "$USERNAME:$PASSWORD" | chpasswd \
    && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' \
         /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
