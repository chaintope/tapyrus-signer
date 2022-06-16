FROM --platform=$BUILDPLATFORM rust:1.61.0 as builder

ARG TARGETARCH

RUN echo "TARGETARCH = $TARGETARCH"

WORKDIR /tapyrus-signer

COPY . .

RUN case "$TARGETARCH" in \
        "386") \
            RUST_TARGET="i686-unknown-linux-gnu" \
            ;; \
        "amd64") \
            RUST_TARGET="x86_64-unknown-linux-gnu" \
            ;; \
        "arm64") \
            RUST_TARGET="aarch64-unknown-linux-gnu" \
            ;; \
        *) \
            echo "Doesn't support $TARGETARCH architecture" \
            exit 1 \
            ;; \
        esac && \
    cargo build --target "$RUST_TARGET" --release && \
    mv target/$RUST_TARGET/release/tapyrus-* target/release/

FROM ubuntu:22.04

COPY --from=builder /tapyrus-signer/target/release/tapyrus-signerd /usr/local/bin/
COPY --from=builder /tapyrus-signer/target/release/tapyrus-setup /usr/local/bin/

ENV CONF_FILE='/etc/tapyrus/tapyrus-signer.toml'

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
