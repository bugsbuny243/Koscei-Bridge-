FROM golang:1.26.7-alpine3.24@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS builder
WORKDIR /app
COPY koschei/api/go.mod koschei/api/go.sum ./
RUN go mod download
COPY koschei/api .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/koschei-api .

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime-assets
RUN apk add --no-cache ca-certificates tzdata

FROM scratch
WORKDIR /app
COPY --from=runtime-assets /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-assets /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /out/koschei-api /app/koschei-api
COPY koschei/api/public /app/public
COPY koschei/api/migrations /app/migrations
ENV STATIC_DIR=/app/public
ENV TZ=UTC
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/koschei-api"]