FROM python:3.11-slim

# Install Paramiko and Requests — no OS-level SSH daemon needed
RUN pip install --no-cache-dir paramiko requests

WORKDIR /app
COPY server.py .

# Expose internal SSH port
EXPOSE 22

# Generate a host RSA key at container startup so we don't bake private keys into the image
CMD ["python", "server.py"]
