FROM python:3.11-slim

RUN pip install --no-cache-dir flask requests

WORKDIR /app
COPY server.py .

EXPOSE 9200

CMD ["python", "server.py"]
