## why-agent

[![Docker](https://img.shields.io/badge/Docker-ready-blue)](https://www.docker.com/) [![Python 3.11](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Overview

`why-agent` is an AI-focused project. Update this section with a concise description of your goals, core features, and primary use cases.

## Architecture

This project follows a **Sidecar pattern for LLM security**, where the core LLM application runs alongside a dedicated security sidecar process:

- **Sidecar Security Proxy**: All inbound prompts and outbound LLM responses are routed through a separate sidecar service running next to the main application (for example, as a companion container in the same pod). This proxy acts as an enforcement point, isolating security-critical logic from application code.
- **Policy & Guardrails Engine**: The sidecar evaluates requests and responses against configurable policies (e.g., data loss prevention, PII redaction, prompt injection defenses, and tenant-isolation rules) before anything reaches the LLM or is returned to the caller.
- **Observability & Auditing**: The sidecar centralizes logging, metrics, and audit trails of all LLM interactions, enabling incident response, anomaly detection, and compliance reporting without modifying application business logic.
- **Zero-Trust Integration**: Authentication, authorization, rate limiting, and context filtering are performed in the sidecar, allowing you to plug in different LLM providers or models while keeping a consistent, hardened security boundary.

By decoupling security controls into a sidecar, teams can iterate on guardrails and compliance requirements independently of the application release cycle, while keeping sensitive data and model access tightly governed.

## Getting Started

- **Prerequisites**: Ensure you have **Docker** and **Python 3.11** installed.
- **Installation**: Add Poetry or your chosen dependency manager setup instructions here.
- **Running locally**: Describe how to start the application (for example, `docker compose up` or `poetry run ...`).
