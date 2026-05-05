# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM rust:1.78-slim AS builder

# Dipendenze di sistema per OpenSSL e linking statico
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache layer: scarica dipendenze prima di copiare il sorgente
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null; true
RUN rm -rf src

# Build reale
COPY src ./src
# Forza ricompilazione dei sorgenti modificati
RUN touch src/main.rs
RUN cargo build --release

# ── Stage 2: runtime minimale ───────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Utente non-root dedicato
RUN useradd --uid 1001 --no-create-home --shell /usr/sbin/nologin vault

WORKDIR /app
COPY --from=builder /build/target/release/myvault ./myvault

# Permessi minimi
RUN chown vault:vault vault-service && chmod 500 vault-service

USER vault

# Porta esposta (configurabile via VAULT_BIND_ADDR)
EXPOSE 8080

# Health check per Docker / Kubernetes
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fs http://localhost:8080/health || exit 1

ENTRYPOINT ["./myvault"]