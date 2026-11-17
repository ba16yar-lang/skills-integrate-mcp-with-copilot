FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src

RUN useradd --system --uid 10001 --create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "uvicorn src.app:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips=\"${TRUSTED_PROXY_IPS:-127.0.0.1}\" --workers 2"]
