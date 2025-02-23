#!/bin/bash

# Update package list
apt-get update

# Install required dependencies
apt-get install -y curl gnupg2 apt-transport-https

# Add Microsoft repository for ODBC driver
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
add-apt-repository "$(curl -s https://packages.microsoft.com/config/ubuntu/20.04/prod.list)"

# Install Microsoft ODBC Driver for SQL Server
apt-get update
apt-get install -y msodbcsql17 unixodbc-dev

# Verify installation
odbcinst -q -d
