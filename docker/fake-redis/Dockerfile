FROM python:3.11-slim

RUN pip install --no-cache-dir requests

WORKDIR /app
COPY server.py .

EXPOSE 6379

CMD ["python", "server.py"]
