"""Test helper to import the fake-auth Flask app for testing."""
import sys
import os

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import server.py from docker/fake-auth
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "docker", "fake-auth"))

from server import app  # noqa: E402
