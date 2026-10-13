# ── Build stage ───────────────────────────────────────────────────────────────
# The workspace is rustls end to end (kube's rustls-tls, reqwest's `rustls`
# feature, vaultrs's default) — no OpenSSL needed at build or run time.
FROM rust:1-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS builder

WORKDIR /build

# Cache dependency compilation separately from source changes: manifests
# first, every crate stubbed, deps built, then the real sources.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN find crates -name '*.rs' -delete && \
    for crate in crates/*/; do \
      mkdir -p "$crate/src" && echo "pub fn _stub() {}" > "$crate/src/lib.rs"; \
    done && \
    for bin in operator crdgen importer; do echo "fn main() {}" > "crates/$bin/src/main.rs"; done

# --locked: build exactly what Cargo.lock resolves — the image must not
# resolve a dependency the repository never saw. Failure is tolerated here
# only because stubs may not satisfy every crate; the real build below is
# the one that gates.
RUN cargo build --locked --release -p operator -p importer 2>/dev/null; exit 0

COPY crates/ crates/
RUN find crates -name '*.rs' -exec touch {} + && \
    cargo build --locked --release -p operator -p importer

# ── Runtime image ─────────────────────────────────────────────────────────────
# distroless/cc on Debian 13 matches trixie's glibc ABI (the builder's) and
# ships ca-certificates — no shell, no package manager, minimal surface for
# a network-facing webhook. Debian 12's still carried High libssl3 findings
# when this moved.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime

COPY --from=builder /build/target/release/operator /usr/local/bin/operator
# The adoption tool, runnable from the same image (docs: "Migration").
COPY --from=builder /build/target/release/weebo-forgejo-importer /usr/local/bin/weebo-forgejo-importer

# 65532 is distroless's `nonroot`. Numeric so Kubernetes can enforce
# `runAsNonRoot` without resolving names; the Helm chart pins the same UID.
USER 65532:65532

# Static OCI metadata; version, revision and created are added by the
# publish workflow (build-push-action `labels:`).
LABEL org.opencontainers.image.title="weebo-forgejo-operator" \
      org.opencontainers.image.description="Kubernetes operator managing Forgejo objects as CRDs" \
      org.opencontainers.image.source="https://github.com/batleforc/weebo-forgejo" \
      org.opencontainers.image.url="https://github.com/batleforc/weebo-forgejo" \
      org.opencontainers.image.documentation="https://batleforc.github.io/weebo-forgejo" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="batleforc"

ENTRYPOINT ["/usr/local/bin/operator"]
