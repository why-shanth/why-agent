# Production-ready Dockerfile for the why-agent sidecar
# Targeting multi-arch via the official Python base image.

FROM python:3.11-slim-bookworm

# Ensure Python behaves well in containers and configure Poetry.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VERSION=1.8.4 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

# Make Poetry available on PATH for all subsequent layers.
ENV PATH="${POETRY_HOME}/bin:${PATH}"

# Install system dependencies (build-essential for native wheels, curl for healthchecks & Poetry installer).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry via the official installer (avoids using pip directly).
RUN curl -sSL https://install.python-poetry.org | python -

WORKDIR /app

# Copy dependency definitions first to leverage Docker layer caching.
COPY pyproject.toml poetry.lock ./

# Install only main (non-dev) dependencies into the container environment.
RUN poetry install --no-root --only main --no-ansi

# Copy the rest of the application source code.
COPY . .

# Create a non-root user and adjust ownership.
RUN useradd --create-home --uid 1000 whyagent \ 
    && chown -R whyagent:whyagent /app

USER whyagent

EXPOSE 8000

# Entrypoint: run the FastAPI app with uvicorn in production mode.
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
