FROM python:3.12-slim

LABEL maintainer="xunzhang85"
LABEL description="CTF Agent - AI-Powered CTF Auto-Solver Sandbox"

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    netcat-openbsd \
    gdb \
    radare2 \
    binwalk \
    strings \
    file \
    openssl \
    exiftool \
    foremost \
    tshark \
    john \
    hashcat \
    steghide \
    sqlmap \
    nikto \
    gobuster \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash ctfuser

# Set up workspace
WORKDIR /workspace
RUN chown ctfuser:ctfuser /workspace

# Install Python dependencies
COPY pyproject.toml /tmp/
RUN pip install --no-cache-dir /tmp/ 2>/dev/null || \
    pip install --no-cache-dir openai anthropic pyyaml rich click httpx pydantic

# Copy agent code
COPY src/ /opt/agent/
ENV PYTHONPATH=/opt/agent

# Switch to non-root user
USER ctfuser

# Default command
ENTRYPOINT ["python3", "-m", "agent.cli"]
CMD ["--help"]
