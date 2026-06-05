FROM ctsrd/cheribsd-sdk-qemu-morello-purecap:latest

# Switch to root to install host container dependencies
USER root
RUN apt-get update && apt-get install -y \
    pkg-config \
    make \
    cmake \
    libarchive-dev \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Switch back to the unprivileged user expected by cheribuild
USER cheri

# Persist workspace path for Makefile use
ENV WORKSPACE=/workspace
WORKDIR ${WORKSPACE}
