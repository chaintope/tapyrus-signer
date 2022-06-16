FROM --platform=$BUILDPLATFORM rust:1.61.0 as builder

ARG TARGETARCH

RUN echo "TARGETARCH = $TARGETARCH"

WORKDIR /tapyrus-signer

ENV TARGET_ARM "aarch64-unknown-linux-gnu"
ENV TARGET_X86 "x86_64-unknown-linux-gnu"

COPY . .

RUN if [ "$TARGETARCH" = "arm64" ]; then RUST_TARGET=$TARGET_ARM; else RUST_TARGET=$TARGET_X86; fi && \
    rustup target add "$RUST_TARGET" && \
    rustup toolchain install "stable-$RUST_TARGET" && \
    cargo build --target "$RUST_TARGET" --release && \
    mv target/$RUST_TARGET/release/tapyrus-* target/release/

FROM ubuntu:22.04

COPY --from=builder /tapyrus-signer/target/release/tapyrus-signerd /usr/local/bin/
COPY --from=builder /tapyrus-signer/target/release/tapyrus-setup /usr/local/bin/

ENV CONF_FILE='/etc/tapyrus/tapyrus-signer.toml'

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
