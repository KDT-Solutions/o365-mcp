# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04 AS powershell
FROM python:3.12-bookworm
USER root
COPY --from=powershell /opt/microsoft/powershell/7 /opt/microsoft/powershell/7
RUN --mount=type=secret,id=system_ca \
    if [ -f /run/secrets/system_ca ]; then export SSL_CERT_FILE=/run/secrets/system_ca; fi; \
    apt-get -o Acquire::https::CaInfo="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" update && \
    apt-get -o Acquire::https::CaInfo="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" install -y --no-install-recommends libicu72 libgssapi-krb5-2 && \
    rm -rf /var/lib/apt/lists/* && ln -s /opt/microsoft/powershell/7/pwsh /usr/local/bin/pwsh
ARG EXO_VERSION=3.9.0
RUN --mount=type=secret,id=system_ca \
    if [ -f /run/secrets/system_ca ]; then export SSL_CERT_FILE=/run/secrets/system_ca; fi; \
    pwsh -NoProfile -Command "Install-Module ExchangeOnlineManagement -RequiredVersion ${EXO_VERSION} -Scope AllUsers -Repository PSGallery -Force -AcceptLicense"
RUN groupadd --gid 10001 mcp && useradd --uid 10001 --gid 10001 --create-home mcp && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY src ./src
COPY scripts/exchange.ps1 ./scripts/exchange.ps1
RUN chmod 0755 /app /app/scripts && chmod 0644 /app/scripts/exchange.ps1
RUN --mount=type=secret,id=system_ca \
    if [ -f /run/secrets/system_ca ]; then export PIP_CERT=/run/secrets/system_ca; fi; \
    python3 -m pip install --no-cache-dir -r requirements.lock && python3 -m pip install --no-cache-dir --no-deps --no-build-isolation .
ARG APP_VERSION=dev
ARG APP_COMMIT=unknown
ARG APP_BUILD_DATE=unknown
LABEL org.opencontainers.image.source=https://github.com/KDT-Solutions/o365-mcp
USER 10001:10001
ENV HOME=/home/mcp PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    APP_VERSION=${APP_VERSION} APP_COMMIT=${APP_COMMIT} APP_BUILD_DATE=${APP_BUILD_DATE}
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
CMD ["m365-mcp"]
