# syntax=docker/dockerfile:1
# NoraSign Container Image
# IF4020 Kriptografi Semester 1 2026/2027
# Architecture: linux/amd64

FROM python:3.10-slim-bullseye

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY pyproject.toml .
COPY norasign/ norasign/

# Install norasign package
RUN pip install --no-cache-dir -e .

# Create a non-root default user and set permissions for mount points
RUN groupadd -g 1000 norasign && \
    useradd -u 1000 -g norasign -s /bin/bash -m norasign && \
    mkdir -p /input /output /run && \
    chmod 777 /input /output /run

# Default working directory
WORKDIR /work

# Entrypoint directly invokes norasign CLI
ENTRYPOINT ["norasign"]
