#!/bin/bash

export $(grep -v '^#' .env | xargs)

docker-compose up -d

echo "Aguardando o PostgreSQL iniciar..."
until docker exec $POSTGRES_CONTAINER_NAME pg_isready -U $POSTGRES_USER; do
  sleep 2
done

echo "Script executado com sucesso!"
