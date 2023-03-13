#!/bin/sh

if [ "$1" = "postgres" ]; then
    echo "Starting PostgreSQL..."
    /usr/local/bin/docker-entrypoint.sh postgres &
    until pg_isready -q -h db -p 5432 -U myuser; do
        echo "Waiting for database to start..."
        sleep 2
    done
    echo "Creating mydb database..."
    createdb sql_injection_detection -h db -U myuser
    echo "PostgreSQL started successfully!"
fi

exec "$@"
