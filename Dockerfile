# Build the manager binary
FROM golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager ./cmd/main.go

# Use Red Hat UBI Micro as minimal base image to package the manager binary
# UBI Micro is the Red Hat equivalent to distroless - minimal, secure, and supportable
# Refer to https://www.redhat.com/en/blog/introduction-ubi-micro for more details
FROM registry.access.redhat.com/ubi9/ubi-micro:latest

# OpenShift runs containers with arbitrary UIDs, so we need to:
# 1. Set ownership to root group (GID 0)
# 2. Grant group permissions for any directories that need to be written to
# 3. Use a non-root user, but don't hardcode the UID
WORKDIR /
COPY --from=builder --chown=1001:0 /workspace/manager .

# Make the binary executable by the root group (required for OpenShift)
RUN chmod g+x /manager

# Use a non-root user by default (UID 1001)
# OpenShift will override this with a random UID in the same group (GID 0)
USER 1001

ENTRYPOINT ["/manager"]
