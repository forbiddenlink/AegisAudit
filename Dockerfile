FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (npm for node checks)
RUN apt-get update && apt-get install -y \
    npm \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY pyproject.toml .
# Allow pip to install system-wide
RUN pip install .

# Copy source
COPY . .

# Install the package
RUN pip install -e .

# Entrypoint
ENTRYPOINT ["aegis"]
CMD ["--help"]
