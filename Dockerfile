FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AUDIT_LOG=/app/audit/guardrails.jsonl
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 app && mkdir -p /app/audit && chown -R app /app
USER app
EXPOSE 8000
CMD ["agentguard", "serve", "--port", "8000"]
