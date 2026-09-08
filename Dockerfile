# Pinned by digest for reproducible builds (tag = python:3.11-slim).
FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

WORKDIR /app

# Install system dependencies (npm for node dependency checks, git for scans)
RUN apt-get update && apt-get install -y --no-install-recommends \
    npm \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the whole project BEFORE installing: the build backend (hatchling) reads
# README.md at metadata-generation time, so `pip install` fails if only
# pyproject.toml is present. This is why the previous two-stage COPY was broken.
COPY . .

RUN pip install --no-cache-dir .

# Drop root: the scanner never needs privilege, and running as root turns any
# parser/dependency bug into a container-escape primitive (trivy DS-0002). Scan
# output goes to the working directory, so run from a mounted, writable volume,
# e.g. `docker run -v "$PWD:/work" -w /work aegis audit .`.
RUN useradd --create-home --uid 10001 appuser
USER appuser

# Entrypoint
ENTRYPOINT ["aegis"]
CMD ["--help"]
