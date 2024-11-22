#!/bin/bash

set -euo pipefail

# Function to determine the container runtime (docker or podman)
get_container_runtime() {
  if command -v docker &>/dev/null; then
    echo "docker"
  elif command -v podman &>/dev/null; then
    echo "podman"
  else
    echo "No container runtime found. Please install Docker or Podman."
    exit 1
  fi
}

# Function to print text in red
red_echo() {
  echo -e "\033[0;31m$1\033[0m"
}

CONTAINER_RUNTIME=$(get_container_runtime)

red_echo "(build/clean):"
read ACTION

IMAGE_NAME="nt-secure:latest"
CONTAINER_NAME="nt-secure"

if [ "$ACTION" == "build" ]; then
  red_echo "Building $CONTAINER_RUNTIME image..."
  if $CONTAINER_RUNTIME build -t $IMAGE_NAME .; then
    red_echo "$CONTAINER_RUNTIME image built successfully."
  else
    red_echo "Failed to build $CONTAINER_RUNTIME image."
    exit 1
  fi

  red_echo "Running $CONTAINER_RUNTIME container..."
  if $CONTAINER_RUNTIME run -d -p 3000:3000 \
    --cap-add=NET_ADMIN \
    --volume $(pwd):/app \
    --name $CONTAINER_NAME $IMAGE_NAME; then
    red_echo "$CONTAINER_RUNTIME container started successfully."
    $CONTAINER_RUNTIME exec --detach --workdir /app $CONTAINER_NAME bash -c 'cargo build --release && cargo run --bin apiserver'
  else
    red_echo "Failed to start $CONTAINER_RUNTIME container."
    exit 1
  fi

  red_echo "Waiting for the container to start..."
  sleep 5

  URL="http://localhost:3000"

  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")

  if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
    red_echo "success, now you can connect by $URL"
  else
    red_echo "failed"
  fi

elif [ "$ACTION" == "clean" ]; then
  red_echo "Stopping and removing $CONTAINER_RUNTIME container..."
  if $CONTAINER_RUNTIME stop $CONTAINER_NAME; then
    red_echo "Container stopped."
  else
    red_echo "Failed to stop container or container not running."
  fi

  if $CONTAINER_RUNTIME rm $CONTAINER_NAME; then
    red_echo "Container removed."
  else
    red_echo "Failed to remove container or container not found."
  fi

  red_echo "Removing $CONTAINER_RUNTIME image..."
  if $CONTAINER_RUNTIME rmi $IMAGE_NAME; then
    red_echo "Image removed."
  else
    red_echo "Failed to remove image or image not found."
  fi

else
  exit 1
fi
