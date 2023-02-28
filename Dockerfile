FROM ubuntu:latest

USER root
ENV USER root

RUN apt clean
RUN apt-get update \
    && apt-get install -y \
    apt-utils \
    curl \
    gcc \
    rsyslog \
    clang \ 
    lldb \ 
    lld \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl https://sh.rustup.rs -sSf > /tmp/rustup-init.sh \
    && chmod +x /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y \
    && rm -rf /tmp/rustup-init.sh

ENV PATH="/root/.cargo/bin:${PATH}"

# Install nightly rust.
RUN ~/.cargo/bin/rustup toolchain install nightly --component rust-src

# Install bpf-linker
RUN cargo install bpf-linker --config net.git-fetch-with-cli=true

COPY . .

RUN cargo xtask build-ebpf
RUN cargo build
RUN cargo xtask run