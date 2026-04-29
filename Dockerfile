# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/github/gh-aw-threat-detection/pkg/detector.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o /threat-detect ./cmd/threat-detect

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates git

COPY --from=builder /threat-detect /usr/local/bin/threat-detect

# Create non-root user
RUN adduser -D -u 1000 detector
USER detector

WORKDIR /workspace

ENTRYPOINT ["threat-detect"]
