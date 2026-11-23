FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# TLS for DoH/DoT requires system CA bundle
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies without relying on BuildKit-only cache mounts.  Personal
# DNS can be deployed to older VPS Docker installations that still use the
# classic builder, and pip's cache must not remain in the runtime image.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Make the application layer follow the exact source bundle while keeping the
# slower dependency layers cacheable across deployments.
ARG EASYPI_SOURCE_SHA256
LABEL org.easypi.netprotection.source-sha256=$EASYPI_SOURCE_SHA256

# Copy application code into package directory and fail the image build if a
# required runtime module was omitted from the build context.
COPY . /app/easypi_netprotection
ENV PYTHONPATH=/app
RUN test -s /app/easypi_netprotection/system/bootstrap.py

# Validate imports and run the service with the same unprivileged identity used
# by the deployment command.  This catches directory-permission regressions at
# image-build time and provides defense in depth if --user is ever omitted.
USER 65532:65532
RUN python -c "from easypi_netprotection.system.bootstrap import Bootstrap"

# Expose DNS (UDP/TCP) and DoH/DoT ports
EXPOSE 53/udp 53/tcp 8053 853

# Default entrypoint uses built-in config/environment
CMD ["python", "-m", "easypi_netprotection"]
