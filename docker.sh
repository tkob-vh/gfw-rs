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

CONTAINER_RUNTIME=$(get_container_runtime)

echo "(build/clean):"
read ACTION

IMAGE_NAME="nt-secure:latest"
CONTAINER_NAME="nt-secure"

if [ "$ACTION" == "build" ]; then
  echo "Building $CONTAINER_RUNTIME image..."
  if $CONTAINER_RUNTIME build -t $IMAGE_NAME .; then
    echo "$CONTAINER_RUNTIME image built successfully."
  else
    echo "Failed to build $CONTAINER_RUNTIME image."
    exit 1
  fi

  echo "Running $CONTAINER_RUNTIME container..."
  if $CONTAINER_RUNTIME run -d -p 3000:3000 --cap-add=NET_ADMIN --name $CONTAINER_NAME $IMAGE_NAME; then
    echo "$CONTAINER_RUNTIME container started successfully."
  else
    echo "Failed to start $CONTAINER_RUNTIME container."
    exit 1
  fi

  echo "Waiting for the container to start..."
  sleep 5

  URL="http://localhost:3000"

  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")

  if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
    echo "success, now you can connect by $URL"
  else
    echo "failed"
  fi

elif [ "$ACTION" == "clean" ]; then
  echo "Stopping and removing $CONTAINER_RUNTIME container..."
  if $CONTAINER_RUNTIME stop $CONTAINER_NAME; then
    echo "Container stopped."
  else
    echo "Failed to stop container or container not running."
  fi

  if $CONTAINER_RUNTIME rm $CONTAINER_NAME; then
    echo "Container removed."
  else
    echo "Failed to remove container or container not found."
  fi

  echo "Removing $CONTAINER_RUNTIME image..."
  if $CONTAINER_RUNTIME rmi $IMAGE_NAME; then
    echo "Image removed."
  else
    echo "Failed to remove image or image not found."
  fi

else
  exit 1
fi

