FROM python:3.11-slim

RUN pip install --no-cache-dir impacket==0.12.0 requests

WORKDIR /app
COPY server.py .

EXPOSE 445

CMD ["python", "server.py"]
