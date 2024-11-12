#!/bin/bash

echo "(build/clean):"
read ACTION

IMAGE_NAME="nt-secure:latest"
CONTAINER_NAME="nt-secure"

if [ "$ACTION" == "build" ]; then
    echo "Building Docker image..."
    if sudo docker build -t $IMAGE_NAME .; then
        echo "Docker image built successfully."
    else
        echo "Failed to build Docker image."
        exit 1
    fi

    echo "Running Docker container..."
    if sudo docker run -d -p 3000:3000 --name $CONTAINER_NAME $IMAGE_NAME; then
        echo "Docker container started successfully."
    else
        echo "Failed to start Docker container."
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
    echo "Stopping and removing Docker container..."
    if sudo docker stop $CONTAINER_NAME; then
        echo "Container stopped."
    else
        echo "Failed to stop container or container not running."
    fi

    if sudo docker rm $CONTAINER_NAME; then
        echo "Container removed."
    else
        echo "Failed to remove container or container not found."
    fi

    echo "Removing Docker image..."
    if sudo docker rmi $IMAGE_NAME; then
        echo "Image removed."
    else
        echo "Failed to remove image or image not found."
    fi

else
    exit 1
fi