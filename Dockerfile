FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
ENV PORT=8080
# LEGACY_URL, LEGACY_USER, LEGACY_PASSWORD, TURNSTILE_AGENTS_FILE and TURNSTILE_RESOURCE_URL
# come from the Cloud Run service definition (see infra/).
CMD ["sh", "-c", "uvicorn --factory turnstile.cli:create_gateway_app --host 0.0.0.0 --port ${PORT}"]
