FROM alpine:edge

RUN apk add --no-cache ca-certificates curl gcc musl-dev \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain nightly-2026-11-09

ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup component add clippy rust-src --toolchain nightly-2026-11-09

WORKDIR /work

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo .cargo/
COPY src ./src
COPY tests ./tests

RUN cargo fetch --locked

CMD ["sh"]
