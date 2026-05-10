# Multi-stage Dockerfile for local builds (CI uses Dockerfile.goreleaser).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dvarapala ./cmd/dvarapala

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dvarapala /usr/bin/dvarapala
COPY policies /etc/dvarapala/policies
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/dvarapala"]
