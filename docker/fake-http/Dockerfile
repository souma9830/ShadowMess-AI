FROM python:3.11-slim

# Install Flask and Requests
RUN pip install --no-cache-dir flask requests gunicorn

WORKDIR /app
COPY server.py .

# Expose port 80
EXPOSE 80

# Run Flask app with production server (Gunicorn) or directly
# Let's run via gunicorn for stability, or python server.py directly.
# Since it needs custom port binding or standard binding, let's run python server.py.
CMD ["python", "server.py"]
