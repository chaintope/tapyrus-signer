# Cargo.lock pins libc 0.2.189, which requires rustc >=1.65 to build (libc bumped its
# MSRV after this image was originally pinned at 1.61.0) -- bump alongside any future
# `cargo update` that raises a dependency's MSRV past whatever this is pinned to.
FROM rust:1.82-bookworm AS builder

WORKDIR /tapyrus-signer

COPY . .

RUN cargo build --release

# debian:bookworm-slim, not ubuntu:22.04 -- matches the builder's Debian release so
# the glibc the binary was linked against (bookworm's) is the same one running it,
# not an older glibc (ubuntu:22.04 ships an older one than bookworm) a newer-glibc
# binary won't run against.
FROM debian:bookworm-slim

COPY --from=builder /tapyrus-signer/target/release/tapyrus-signerd /usr/local/bin/
COPY --from=builder /tapyrus-signer/target/release/tapyrus-setup /usr/local/bin/

ENV CONF_FILE='/etc/tapyrus/tapyrus-signer.toml'

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]
