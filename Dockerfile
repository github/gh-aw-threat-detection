# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/github/gh-aw-threat-detection/pkg/detector.Version=${VERSION}" -o /threat-detect ./cmd/threat-detect

# Runtime stage
FROM alpine:3.20

COPY --from=builder /threat-detect /usr/local/bin/threat-detect

# Create non-root user
RUN adduser -D -u 1000 detector
USER detector

WORKDIR /workspace

ENTRYPOINT ["threat-detect"]
