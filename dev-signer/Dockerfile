FROM rust:1.85-slim-bookworm AS builder
WORKDIR /build

COPY token-core ./token-core
COPY dev-signer ./dev-signer

WORKDIR /build/dev-signer
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app

COPY --from=builder /build/dev-signer/target/release/dev-signer ./dev-signer
COPY dev-signer/keys ./keys

ENV PARAM_SET=192f
ENV SEC_KEY_PATH=/app/keys/sec.key
ENV PUB_KEY_PATH=/app/keys/pub.key
ENV PORT=7878

EXPOSE 7878
ENTRYPOINT ["./dev-signer"]
