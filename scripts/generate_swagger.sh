#!/bin/bash

# Install swag if not already installed
if ! command -v swag &> /dev/null; then
    echo "Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
fi

# Generate Swagger documentation (docs.go = API metadata; consoleapi = handlers)
echo "Generating Swagger documentation..."
swag init \
  -g docs.go \
  -d satellite/console/consoleweb,satellite/console/consoleweb/consoleapi,satellite/console/consoleweb/staticapi \
  -o satellite/console/consoleweb/swagger \
  --parseDependency \
  --parseInternal

# Create swagger directory if it doesn't exist
mkdir -p swagger

# Copy generated files to swagger directory and embedded swaggerui (served at /swagger/)
cp satellite/console/consoleweb/swagger/swagger.json swagger/
cp satellite/console/consoleweb/swagger/swagger.yaml swagger/
cp satellite/console/consoleweb/swagger/swagger.json satellite/console/consoleweb/swaggerui/

echo "Swagger documentation generated successfully!" 