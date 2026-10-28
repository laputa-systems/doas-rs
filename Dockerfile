FROM alpine:edge

RUN apk add --no-cache ca-certificates curl gcc musl-dev \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain nightly-2026-09-15

ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup component add clippy rust-src --toolchain nightly-2026-09-15

WORKDIR /work

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src

RUN cargo fetch --locked

CMD ["sh"]
