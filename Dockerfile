# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Create an 'uploads' directory and ensure the app user can write to it
# Also create a directory for the database if it's not in /app (though yours is)
RUN mkdir -p /app/uploads /app/data && chown -R www-data:www-data /app/uploads /app/data
# If tickets.db is always created in /app, then /app/data might not be strictly necessary
# but good if you decide to move it later.

# Install system dependencies that might be needed by Python packages (if any)
# For example, if some libraries needed build tools:
# RUN apt-get update && apt-get install -y --no-install-recommends gcc build-essential && rm -rf /var/lib/apt/lists/*
# For now, we'll assume most common Python packages don't need extra system libs with python:3.10-slim

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose the port the app runs on
EXPOSE 5001

# Define environment variables that might be needed at runtime
# These are placeholders; actual values should be provided when running the container.
ENV FLASK_APP=server.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_DEBUG=0 
# ENV GOOGLE_API_KEY="your_google_api_key_here" # Better to pass this at runtime
# ENV FLASK_SECRET_KEY="your_flask_secret_key_here" # Better to pass this at runtime
# ENV EMAIL_USER="your_email_user_here" # Better to pass this at runtime
# ENV EMAIL_APP_PASSWORD="your_email_app_password_here" # Better to pass this at runtime
# ENV PASSWORD="your_email_app_password_from_env_again_here" # (This seems redundant if EMAIL_APP_PASSWORD is used)

# Set a non-root user to run the application for better security
# The www-data user is common for web servers and should have been created by the base image or apt
USER www-data

# Command to run the application using eventlet (good for Flask-SocketIO)
# Ensure eventlet is in your requirements.txt
# ...
CMD ["python", "server.py"]
# CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "wsgi:app", "--bind", "0.0.0.0:5001"]
# The wsgi.py file will be a small wrapper to run the SocketIO app.