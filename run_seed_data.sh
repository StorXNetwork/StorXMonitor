#!/bin/bash
# Script to insert dummy OAuth2 requests data
# Usage: ./run_seed_data.sh [database_name] [username]

DB_NAME="${1:-postgres}"
DB_USER="${2:-dhaval}"

echo "Attempting to connect to database: $DB_NAME as user: $DB_USER"
echo ""

# Try to connect and run the script
psql -U "$DB_USER" -d "$DB_NAME" -f insert_dummy_oauth2_requests.sql

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully inserted dummy data!"
else
    echo ""
    echo "❌ Failed to insert data. Trying alternative methods..."
    echo ""
    echo "Alternative options:"
    echo "1. Copy the SQL content and paste into your database client (pgAdmin, DBeaver, etc.)"
    echo "2. Use: psql -U $DB_USER -d $DB_NAME < insert_dummy_oauth2_requests.sql"
    echo "3. Check your database connection string from your application config"
fi

