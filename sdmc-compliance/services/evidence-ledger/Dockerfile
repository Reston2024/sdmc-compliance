FROM python:3.10-slim

WORKDIR /app

# Install build tooling
RUN pip install --no-cache-dir hatchling

# Copy dependency manifest first for layer caching
COPY pyproject.toml .

# Install production dependencies only (no dev extras)
RUN pip install --no-cache-dir .

# Copy application source
COPY app/ ./app/

# Per NIST SP 800-53 AC-6 (Least Privilege) - run as non-root
RUN adduser --system --no-create-home --group appuser
USER appuser

# Document the port
EXPOSE 8000

# Health check for docker compose depends_on
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/ready')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
