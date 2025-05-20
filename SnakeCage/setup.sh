#!/bin/bash

# SnakeCage Setup Script
# Copyright (c) 2023-2025 jaafaraltayarC

echo "Setting up SnakeCage..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask flask-sqlalchemy gunicorn psutil psycopg2-binary werkzeug email-validator

# Create reports directory
mkdir -p reports

echo "Setup complete! Run the application with:"
echo "source venv/bin/activate"
echo "gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app"