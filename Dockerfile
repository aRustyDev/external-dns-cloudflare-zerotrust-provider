# syntax=docker/dockerfile:1
# The build stage always runs on the builder's own platform and cross-compiles. The webhook is pure
# Go (CGO_ENABLED=0), so Go targets another architecture natively. Running this stage under QEMU
# instead made the arm64 half of a multi-arch build take about fifteen minutes. The final stage has
# no RUN, so assembling either platform's image needs no emulation either.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/webhook ./cmd/webhook

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/webhook /webhook
USER nonroot:nonroot
# 8080 = health/metrics; the webhook API listens on 127.0.0.1:8888 (sidecar-local only).
EXPOSE 8080
ENTRYPOINT ["/webhook"]
