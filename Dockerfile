FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=oci.17166969.xyz/owned-tools@sha256:aaec19e7a44cbc53b40db2d22093600ee888689b89be94da90e5398ed02f1883 /opt/laputa /opt/laputa
ENV PATH=$PATH:/opt/laputa/bin

ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_X86_64_SHA256=331228566cc931f32cd684f9bebc5956a5e5d7394c8d5de595f196a658ab98e6
ARG RUSTUP_AARCH64_SHA256=1ddf36182ac5d1782dbeefcb9bea7f5f9412d88f4a0d5047b1564a223624e8c6

RUN apk add --no-cache \
    ca-certificates=20261020-r0 \
    curl=8.23.0-r0 \
    musl-dev=1.2.6-r3

# Rust links host proc-macros against -lgcc_s, which only gcc's package symlinks; the C
# compiler and linker driver is the owned clang.
RUN apk add --no-cache libgcc=15.2.0-r5 \
    && ln -s libgcc_s.so.1 /usr/lib/libgcc_s.so \
    && ln -s /opt/laputa/bin/clang /usr/local/bin/cc

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
