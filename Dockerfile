# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# This module currently has no external dependencies, so the build does not
# install git or other VCS tools. Add them here if future direct VCS-backed
# modules require them.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/github/gh-aw-threat-detection/pkg/detector.Version=${VERSION}" -o /threat-detect ./cmd/threat-detect

# Runtime stage
FROM alpine:3.20

# Keep Alpine's standard CA bundle/package-managed trust store layout.
RUN apk add --no-cache ca-certificates
COPY --from=builder /threat-detect /usr/local/bin/threat-detect

# Create non-root user
RUN adduser -D -u 1000 detector
USER detector

WORKDIR /workspace

ENTRYPOINT ["threat-detect"]
