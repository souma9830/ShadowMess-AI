FROM python:3.11-slim

# Install Flask and Requests
RUN pip install --no-cache-dir flask requests

WORKDIR /app
COPY server.py .

# Expose port 8443
EXPOSE 8443

CMD ["python", "server.py"]
