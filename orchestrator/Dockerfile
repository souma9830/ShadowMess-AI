FROM python:3.11-slim

WORKDIR /app

# Install docker SDK + flask only — minimal attack surface
RUN pip install --no-cache-dir flask docker gunicorn

COPY app.py .

# Run as non-root
RUN useradd -r -u 1001 orchestrator
USER orchestrator

EXPOSE 9000

CMD ["gunicorn", "--bind", "0.0.0.0:9000", "--workers", "1", "--timeout", "60", "app:app"]
