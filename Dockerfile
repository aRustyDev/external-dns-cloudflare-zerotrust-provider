# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/webhook ./cmd/webhook

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/webhook /webhook
USER nonroot:nonroot
# 8080 = health/metrics; the webhook API listens on 127.0.0.1:8888 (sidecar-local only).
EXPOSE 8080
ENTRYPOINT ["/webhook"]
