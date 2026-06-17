#!/bin/bash
set -euo pipefail

DB_NAME="testdb"
DB_USER="appuser"
DB_PASS="apppass"

echo "Checking MySQL installation..."

if ! command -v mysql >/dev/null 2>&1; then
    echo "Error: mysql client not found."
    echo "Please install MySQL."
    exit 1
fi

echo "Checking MySQL server..."

if ! mysqladmin ping >/dev/null 2>&1; then
    echo "MySQL server is not running."

    if command -v systemctl >/dev/null 2>&1; then
        echo "Attempting to start MySQL..."
        sudo systemctl start mysql 2>/dev/null \
            || sudo systemctl start mysqld 2>/dev/null \
            || true
    fi

    if ! mysqladmin ping >/dev/null 2>&1; then
        echo "Could not start MySQL."
        echo "Please start MySQL manually and rerun."
        exit 1
    fi
fi

echo "Checking database setup..."

mysql -uroot <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost'
IDENTIFIED BY '${DB_PASS}';

CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1'
IDENTIFIED BY '${DB_PASS}';

GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';

FLUSH PRIVILEGES;
EOF

echo "Database initialization complete."
echo "Database : ${DB_NAME}"
echo "Username : ${DB_USER}"
echo "Password : ${DB_PASS}"