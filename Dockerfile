# Use official Python image as base
FROM python:3.10

# Set working directory in container
WORKDIR /app

# Install system dependencies for ODBC
RUN apt-get update && apt-get install -y \
    curl gnupg2 apt-transport-https unixodbc unixodbc-dev \
    && curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && add-apt-repository "$(curl -s https://packages.microsoft.com/config/ubuntu/20.04/prod.list)" \
    && apt-get update && apt-get install -y msodbcsql17

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the application port
EXPOSE 5000

# Run the application
CMD ["python", "backend.py"]
