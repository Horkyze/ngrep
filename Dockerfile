# Multi-architecture build environment for ngrep
ARG TARGETARCH
FROM alpine:3.18

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    autoconf \
    automake \
    linux-headers \
    libpcap-dev \
    flex \
    bison

# Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build static ngrep binary using Alpine's musl libc (better for static linking)
RUN ./configure && make static

# Create output directory and copy artifacts
RUN mkdir -p /output && \
    cp ngrep.static /output/ && \
    cp ngrep.8 /output/

# Default command shows build artifacts
CMD ["ls", "-la", "/output/"]