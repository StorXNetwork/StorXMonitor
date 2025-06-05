#!/bin/bash

# Install swag if not already installed
if ! command -v swag &> /dev/null; then
    echo "Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
fi

# Generate Swagger documentation
echo "Generating Swagger documentation..."
swag init -g satellite/console/consoleweb/server.go -o satellite/console/consoleweb/swagger

# Create swagger directory if it doesn't exist
mkdir -p swagger

# Copy generated files to swagger directory
cp satellite/console/consoleweb/swagger/swagger.json swagger/
cp satellite/console/consoleweb/swagger/swagger.yaml swagger/

echo "Swagger documentation generated successfully!" 