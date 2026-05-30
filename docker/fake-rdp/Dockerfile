FROM python:3.11-slim

RUN pip install --no-cache-dir requests==2.31.0

WORKDIR /app
COPY server.py rdp_session.py desktop_bitmap.py .

EXPOSE 3389

CMD ["python", "server.py"]
