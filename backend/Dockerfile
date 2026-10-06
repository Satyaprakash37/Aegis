# Build stage
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final runtime stage
FROM python:3.11-slim AS runner

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    nmap \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Nuclei binary v3.3.8 (ProjectDiscovery)
ARG NUCLEI_VERSION=3.3.8
RUN curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Create non-root system user and prepare nuclei templates directory
RUN mkdir -p /home/appuser /nuclei-templates && \
    addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup --home /home/appuser appuser && \
    nuclei -update-templates -td /nuclei-templates || true && \
    ln -s /nuclei-templates /home/appuser/nuclei-templates && \
    chown -R appuser:appgroup /home/appuser /nuclei-templates

ENV NUCLEI_TEMPLATES_DIR=/nuclei-templates

COPY --from=builder /install /usr/local

COPY --chown=appuser:appgroup . .

RUN chmod +x /app/entrypoint.sh && \
    mkdir -p /app/reports && \
    chown -R appuser:appgroup /app/reports

USER appuser

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
