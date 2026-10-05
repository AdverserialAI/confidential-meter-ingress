# syntax=docker/dockerfile:1.7
# The release workflow passes these explicitly. Keeping them required prevents
# an image whose declared architecture differs from its Go binary.
ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

FROM --platform=$BUILDPLATFORM golang:1.24.0-alpine3.21@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/meter-ingress ./cmd/meter-ingress

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build --chown=nonroot:nonroot /out/meter-ingress /meter-ingress
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/meter-ingress"]
