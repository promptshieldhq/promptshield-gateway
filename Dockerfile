FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o promptshield \
    ./cmd/proxy

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S promptshield && \
    adduser -S -G promptshield promptshield

WORKDIR /app

COPY --from=builder /build/promptshield .

USER promptshield

EXPOSE 8080

# Policy is mounted at runtime via -v ./config/policy.yaml:/app/config/policy.yaml
ENTRYPOINT ["./promptshield"]
CMD ["serve"]
