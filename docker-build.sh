#!/bin/bash

# Docker build script for ngrep
# This script builds static ngrep binaries for AMD64 and ARM64 architectures

set -e

IMAGE_NAME="ngrep-builder"
BIN_DIR="bin"

# Create bin directory
mkdir -p $BIN_DIR

# Clean up any existing containers
docker rm -f ${IMAGE_NAME}-amd64 ${IMAGE_NAME}-arm64 ngrep-build-amd64 ngrep-build-arm64 2>/dev/null || true

# Build for AMD64
echo "Building for AMD64..."
CONTAINER_NAME_AMD64="ngrep-build-amd64"
docker buildx build --platform linux/amd64 -t ${IMAGE_NAME}-amd64 .
docker run --name $CONTAINER_NAME_AMD64 --platform linux/amd64 ${IMAGE_NAME}-amd64
docker cp $CONTAINER_NAME_AMD64:/output/ ./$BIN_DIR-temp-amd64/
mv ./$BIN_DIR-temp-amd64/ngrep.static ./$BIN_DIR/ngrep-amd64
cp ./$BIN_DIR-temp-amd64/ngrep.8 ./$BIN_DIR/
docker rm $CONTAINER_NAME_AMD64
rm -rf ./$BIN_DIR-temp-amd64/

# Build for ARM64
echo "Building for ARM64..."
CONTAINER_NAME_ARM64="ngrep-build-arm64"
docker buildx build --platform linux/arm64 -t ${IMAGE_NAME}-arm64 .
docker run --name $CONTAINER_NAME_ARM64 --platform linux/arm64 ${IMAGE_NAME}-arm64
docker cp $CONTAINER_NAME_ARM64:/output/ ./$BIN_DIR-temp-arm64/
mv ./$BIN_DIR-temp-arm64/ngrep.static ./$BIN_DIR/ngrep-arm64
docker rm $CONTAINER_NAME_ARM64
rm -rf ./$BIN_DIR-temp-arm64/

echo "Build complete! Binaries available in ./$BIN_DIR/"
ls -la $BIN_DIR/