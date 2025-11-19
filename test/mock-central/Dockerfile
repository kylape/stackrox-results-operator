FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build mock-central binary
RUN CGO_ENABLED=0 GOOS=linux go build -o mock-central ./test/mock-central

# Runtime image
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/mock-central .

# Create data directory
RUN mkdir -p /data

# Set environment
ENV DATA_DIR=/data
ENV PORT=8443

EXPOSE 8443

CMD ["./mock-central"]
