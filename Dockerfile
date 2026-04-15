# MCP Shield
# Zero Trust proxy for the Model Context Protocol (MCP)

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY gateway_core.py .
COPY run_gateway.py .
COPY policy.yaml .

# Create logs directory
RUN mkdir -p /app/logs

# Non-root user for security
RUN useradd -r -s /bin/false shield && \
    chown -R shield:shield /app
USER shield

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/health'); r.raise_for_status()" || exit 1

ENTRYPOINT ["python", "run_gateway.py"]
CMD ["--config", "policy.yaml", "--port", "8000"]
