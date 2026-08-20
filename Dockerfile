# Multi-stage Dockerfile for the Athlete Biometrics Secure Cloud Server.
#
# Stage 1 ("builder"): installs dependencies into an isolated virtualenv.
# Stage 2 ("runtime"): copies only the venv + application code into a slim,
# non-root final image — keeping the production image minimal and reducing
# attack surface (no build toolchain present in the shipped image).

FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


FROM python:3.11-slim AS runtime

# Run as a non-root user (production security best practice).
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

# Pre-create the mount point for the persistent volume (docker-compose mounts
# a named volume at /data) and hand ownership to the non-root runtime user,
# since Docker creates volume mount points as root by default.
RUN mkdir -p /data && chown -R appuser:appuser /app /data

USER appuser

ENV ENVIRONMENT=production \
    HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "server.main_server:app", "--host", "0.0.0.0", "--port", "8000"]
