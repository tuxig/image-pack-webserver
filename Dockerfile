FROM golang:1.26-alpine AS builder

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/image-packer .
RUN mkdir -p /out/data/cache /out/data/tmp

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=65532:65532 /out/data /data
COPY --from=builder /out/image-packer /image-packer

USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]

ENV LISTEN_ADDR=:8080
ENV DATA_DIR=/data

ENTRYPOINT ["/image-packer"]
