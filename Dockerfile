# =============================================================================
# Auth N&Z - Multi-Stage Production Dockerfile
# =============================================================================
# Stage 1: Build Dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools for native C-extensions (bcrypt, cffi, asyncpg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# =============================================================================
# Stage 2: Minimal Runtime Image
FROM python:3.12-slim AS runtime

WORKDIR /app

# Install minimal libpq runtime dependency for PostgreSQL
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user for container security
RUN useradd -m -u 1000 authnz

# Copy installed Python dependencies from builder
COPY --from=builder /root/.local /home/authnz/.local

# Copy application source code
COPY --chown=authnz:authnz . .

# Set environment paths and defaults
ENV PATH=/home/authnz/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

USER authnz

EXPOSE 8000

# Container liveness health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Start Uvicorn ASGI production server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
