FROM rust:1.61.0 as builder

WORKDIR /tapyrus-signer

COPY . .

RUN cargo build --release

FROM ubuntu:22.04

RUN apt-get update

COPY --from=builder /tapyrus-signer/target/release/tapyrus-signerd /usr/local/bin/
COPY --from=builder /tapyrus-signer/target/release/tapyrus-setup /usr/local/bin/

ENV CONF_FILE='/etc/tapyrus/tapyrus-signer.toml'

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
