FROM golang:1.19 as builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 go build -o envoy-acme ./cmd/envoy-acme/.


FROM alpine:3.16

RUN apk add --no-cache ca-certificates && update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

COPY --from=builder /app/envoy-acme /envoy-acme
CMD ["/envoy-acme"]
