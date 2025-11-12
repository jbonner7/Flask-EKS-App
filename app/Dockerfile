# --- Stage 1: Build Stage
# Standard Python image for building/installing dependencies
FROM python:3.9-slim as builder

# Install necessary build tools (only needed if using certain compiled Python packages)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy the application source code and requirement files
COPY requirements.txt .
COPY app.py .

# Install Flask and the Basic Authentication library
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: Final Runtime Image ---
# Start from a clean, smaller base image for the final deployment
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy installed dependencies and source code from the build stage
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /app/app.py /app/

# Define the directory for the externally copied scan file
RUN mkdir -p /app/scan_file

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Expose the Flask port
EXPOSE 5000

# Command to run the Flask application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]

# NOTE: The vulnerability report (sbom_output.json) is NOT copied here.
# It will be copied into the running container later via the 'kubectl cp' command 
# from your EC2 orchestration instance.