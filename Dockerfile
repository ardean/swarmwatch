# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
# The release version, for example v0.3.0 or 0.3.0; "dev" for a build that is not a release.
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/ardean/swarmwatch/internal/version.Version=${VERSION#v}" \
    -o /out/swarmwatch ./cmd/swarmwatch

# Trivy is built from its release tag with newer dependencies, because the released binary
# still ships go-jose, x/net and x/crypto versions with known vulnerabilities.
# Once a Trivy release contains these fixes, replace this stage with: FROM aquasec/trivy:<version>
FROM golang:1.27-alpine AS trivy
RUN apk add --no-cache git
ARG TRIVY_VERSION=v0.76.1
RUN git clone -q --depth 1 --branch ${TRIVY_VERSION} https://github.com/aquasecurity/trivy /trivy
WORKDIR /trivy
RUN go get github.com/go-jose/go-jose/v4@v4.1.6 golang.org/x/net@v0.62.0 golang.org/x/crypto@2f1f834330b2
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION#v}" \
    -o /out/trivy ./cmd/trivy

FROM alpine:3.24
# docker-cli: talks to the host daemon via the mounted socket. coreutils: df -B / nproc / cut.
RUN apk add --no-cache docker-cli coreutils ca-certificates tzdata
COPY --from=trivy /out/trivy /usr/local/bin/trivy
COPY --from=build /out/swarmwatch /usr/local/bin/swarmwatch
# Persistent state (vulnerability results, Trivy DB) lives in /data — mount a volume there.
ENV XDG_CACHE_HOME=/data TRIVY_CACHE_DIR=/data/trivy TRIVY_NO_PROGRESS=true TRIVY_DISABLE_TELEMETRY=true
VOLUME /data
EXPOSE 8590
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s CMD wget -qO /dev/null http://127.0.0.1:8590/healthz || exit 1
ENTRYPOINT ["swarmwatch"]
CMD ["serve"]
