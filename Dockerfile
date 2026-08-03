FROM golang:1.25.12-alpine3.24 AS builder
WORKDIR /app
COPY koschei/api/go.mod koschei/api/go.sum ./
RUN go mod download
COPY koschei/api .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/koschei-api .

FROM alpine:3.24.1 AS runtime-assets
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
