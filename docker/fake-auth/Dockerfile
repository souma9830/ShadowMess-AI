FROM python:3.11-slim

# Install Flask and Requests
RUN pip install --no-cache-dir flask requests

WORKDIR /app
COPY docker/fake-auth/server.py .
COPY backend/deception/fake_ad.py .

# Expose port 389
EXPOSE 389

CMD ["python", "server.py"]
