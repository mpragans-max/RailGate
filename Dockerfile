# =============================================================================
# RailGate — Railway Personal Gateway
# Single container: Xray-core (VLESS + REALITY) + FastAPI admin + supervisor.
#
# Build:  docker build -t railgate .
# Update Xray: bump XRAY_VERSION and BOTH checksums below, then rebuild.
#   The checksums come from the release's `.dgst` file, e.g.
#   https://github.com/XTLS/Xray-core/releases/download/<tag>/Xray-linux-64.zip.dgst
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — fetch and cryptographically verify the pinned Xray-core release.
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS xray-fetch

# Pinned, known-good STABLE release (not a pre-release).
ARG XRAY_VERSION=v26.3.27
ARG XRAY_SHA256_AMD64=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
ARG XRAY_SHA256_ARM64=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c
ARG TARGETARCH=amd64

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/xray-dl

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) asset="Xray-linux-64.zip";           sum="${XRAY_SHA256_AMD64}" ;; \
        arm64) asset="Xray-linux-arm64-v8a.zip";    sum="${XRAY_SHA256_ARM64}" ;; \
        *) echo "ERROR: unsupported architecture '${TARGETARCH}'. Railway builds amd64." >&2; exit 1 ;; \
    esac; \
    base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"; \
    curl --fail --silent --show-error --location --retry 3 --max-time 300 -o xray.zip      "${base}/${asset}"; \
    curl --fail --silent --show-error --location --retry 3 --max-time 120 -o xray.zip.dgst "${base}/${asset}.dgst"; \
    # 1) verify against the checksum pinned in this Dockerfile
    echo "${sum}  xray.zip" | sha256sum -c -; \
    # 2) cross-check that the publisher's own digest file agrees with the pin
    grep -qi "SHA2-256= *${sum}" xray.zip.dgst || { echo "ERROR: publisher .dgst does not match pinned checksum" >&2; exit 1; }; \
    unzip -q xray.zip -d extracted; \
    install -Dm755 extracted/xray /opt/xray/xray; \
    install -Dm644 extracted/LICENSE /opt/xray/LICENSE.Xray-core; \
    # geoip.dat/geosite.dat (~30 MB) are intentionally NOT shipped: RailGate's
    # routing uses explicit CIDR literals, so no geo database is required.
    /opt/xray/xray version


# -----------------------------------------------------------------------------
# Stage 2 — runtime image.
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="RailGate" \
      org.opencontainers.image.description="Personal VLESS/REALITY gateway with web admin, built for Railway" \
      org.opencontainers.image.source="https://github.com/Mpratama260304/RailGate" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/railgate \
    APP_ROOT=/opt/railgate \
    DATA_DIR=/data \
    PORT=8080 \
    XRAY_PORT=2443 \
    XRAY_BIN=/usr/local/bin/xray \
    DEBIAN_FRONTEND=noninteractive

# Runtime + diagnostic utilities only (no compilers, no dev headers).
#   curl/wget      - health & outbound checks
#   iproute2       - `ss` for listening sockets
#   procps         - `ps`, `top`
#   dnsutils       - `dig`/`nslookup` for DNS diagnostics
#   netcat-openbsd - TCP reachability checks
#   jq             - JSON inspection of the generated config
#   openssl        - TLS probing of the REALITY destination
#   sqlite3        - inspect/repair the database
#   tmux           - persistent shells over `railway ssh --session`
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        iproute2 \
        procps \
        dnsutils \
        netcat-openbsd \
        jq \
        openssl \
        sqlite3 \
        tmux \
        less \
        tar \
        gzip \
        tzdata; \
    rm -rf /var/lib/apt/lists/*

# Python dependencies first so they stay cached across app code changes.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

# Verified Xray binary from stage 1.
COPY --from=xray-fetch /opt/xray/xray /usr/local/bin/xray
COPY --from=xray-fetch /opt/xray/LICENSE.Xray-core /usr/local/share/LICENSE.Xray-core

WORKDIR /opt/railgate

COPY VERSION       /opt/railgate/VERSION
COPY app/          /opt/railgate/app/
COPY scripts/      /opt/railgate/scripts/
COPY xray/         /opt/railgate/xray/

RUN set -eux; \
    chmod 0755 /opt/railgate/scripts/*.sh /opt/railgate/scripts/vpnctl /opt/railgate/scripts/supervisor.py; \
    ln -sf /opt/railgate/scripts/vpnctl     /usr/local/bin/vpnctl; \
    ln -sf /opt/railgate/scripts/diagnose.sh /usr/local/bin/rg-diagnose; \
    # /data is the mount point for the Railway Volume. It is created here so the
    # container still starts (in ephemeral mode) when no volume is attached.
    mkdir -p /data; \
    chmod 0755 /data; \
    /usr/local/bin/xray version; \
    python3 -c "import fastapi, uvicorn, jinja2, qrcode, argon2, httpx, websockets; print('python deps OK')"

# Informational only. EXPOSE does NOT create public networking on Railway:
#   * 8080 -> Railway "Public Networking" (HTTP). Railway overrides it via $PORT.
#   * 2443 -> Railway "TCP Proxy" must be pointed at this internal port.
EXPOSE 8080/tcp
EXPOSE 2443/tcp

# NOTE: persistent storage at /data is provided by a Railway Volume mounted
# on this service (configure under Service -> Volumes in the dashboard).
# Docker's native VOLUME instruction is intentionally omitted - Railway's
# Dockerfile builder rejects it.

# Local convenience; Railway uses railway.json's healthcheckPath instead.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/opt/railgate/scripts/entrypoint.sh"]
