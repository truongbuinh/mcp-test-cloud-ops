# MCP-073: floating :latest tag on base image
FROM python:latest

WORKDIR /app

# MCP-207: pipes remote script to shell at build time
RUN curl -fsSL https://example.com/install.sh | bash

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# MCP-208: no USER directive — runs as root
CMD ["python", "server.py"]
