#!/bin/bash
if ! [ -f ".env.example" ]; then
  echo ".env.example file not found, stopping script"
  exit 1
fi


if ! [ -f ".env" ]; then
  echo ".env file not found, copying from .env.example"
  cp .env.example .env
fi

export $(grep -v '^#' .env | xargs)

if [ -z "$ACCESS_TOKEN_SECRET" ] || [ -z "$REFRESH_TOKEN_SECRET" ]; then
  echo "Generating new secrets..."
  npm run jwt-secret
fi

echo "Building docker-compose"
docker-compose build

echo "Starting docker-compose"
docker-compose up -d

echo "Aguardando o PostgreSQL iniciar..."
until docker exec $POSTGRES_CONTAINER_NAME pg_isready -U $POSTGRES_USER; do
  sleep 2
done

echo "Script executado com sucesso!"
