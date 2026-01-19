#!/bin/bash
set -euo pipefail

IMAGE_NAME="training-practical-greybox-fuzzing"

SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Build the Docker image
docker build -t ${IMAGE_NAME} \
             --build-arg USER_UID=$(id -u) \
             --build-arg USER_GID=$(id -g) \
             -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}/.."

# Run the Docker container
docker run --rm -it \
           --privileged \
           -v "${SCRIPT_DIR}/../target:/target" \
           --entrypoint=bash \
           ${IMAGE_NAME}
