# Virtual fleet simulator image (multi-stage, distroless, non-root).
#   docker build -t ironmesh-fleet -f device/agent-rs/Dockerfile device/agent-rs
#   docker run --rm -v $PWD/fleet:/fleet ironmesh-fleet run --dir /fleet --config /fleet/fleet.toml
FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY src ./src
RUN cargo build --release --locked --bin ironmesh-fleet --bin ironmesh-agent \
 && strip target/release/ironmesh-fleet target/release/ironmesh-agent

# Debian 13 runtime: the debian12 cc image still ships a libssl3 with a fixed HIGH CVE (the
# binary is rustls/ring only and never loads it). glibc is backward compatible, so the
# bookworm-built binary runs unchanged.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/ironmesh-fleet /usr/local/bin/ironmesh-fleet
USER nonroot:nonroot
WORKDIR /fleet
ENTRYPOINT ["/usr/local/bin/ironmesh-fleet"]
CMD ["--help"]
