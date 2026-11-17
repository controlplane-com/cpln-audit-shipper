# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG IMAGE_VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && go test ./...
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${IMAGE_VERSION}" -o /out/cpln-audit-shipper .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/cpln-audit-shipper /cpln-audit-shipper
LABEL org.opencontainers.image.source="https://github.com/controlplane-com/cpln-audit-shipper" \
      org.opencontainers.image.description="Ships the Control Plane audit trail and mk8s Kubernetes audit logs to S3, syslog or OTLP"
USER nonroot:nonroot
ENTRYPOINT ["/cpln-audit-shipper"]
