FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_X86_64_SHA256=331228566cc931f32cd684f9bebc5956a5e5d7394c8d5de595f196a658ab98e6
ARG RUSTUP_AARCH64_SHA256=1ddf36182ac5d1782dbeefcb9bea7f5f9412d88f4a0d5047b1564a223624e8c6

RUN apk add --no-cache \
    ca-certificates=20261020-r0 \
    curl=8.23.0-r0 \
    gcc=15.2.0-r5 \
    musl-dev=1.2.6-r3

RUN arch="$(apk --print-arch)" \
    && case "$arch" in \
        x86_64) checksum="$RUSTUP_X86_64_SHA256" ;; \
        aarch64) checksum="$RUSTUP_AARCH64_SHA256" ;; \
        *) exit 1 ;; \
    esac \
    && curl --proto '=https' --tlsv1.2 -fSsL \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-musl/rustup-init" \
        -o /tmp/rustup-init \
    && printf '%s  %s\n' "$checksum" /tmp/rustup-init | sha256sum -c - \
    && chmod 755 /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain none \
    && rm /tmp/rustup-init

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /work

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo .cargo/
COPY src ./src
COPY tests ./tests

RUN cargo fetch --locked

CMD ["sh"]
