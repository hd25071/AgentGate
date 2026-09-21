# syntax=docker/dockerfile:1

# The Go image is parameterised so a mirror can be substituted in networks
# where Docker Hub is unreachable, e.g.
#   docker build --build-arg GO_IMAGE=docker.m.daocloud.io/library/golang:1.26-alpine .
#
# Keep this in step with the `go` directive in go.mod. A toolchain older than
# the one go.mod asks for will not build the module as-is: with GOTOOLCHAIN=auto
# it silently downloads a matching toolchain mid-build, and in an air-gapped
# build that turns into a confusing failure instead of a clear one.
ARG GO_IMAGE=golang:1.26-alpine

FROM ${GO_IMAGE} AS build
WORKDIR /src

ENV CGO_ENABLED=0 GOOS=linux
# Module proxy is also parameterised: goproxy.cn is reachable in mainland
# networks where proxy.golang.org is not.
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY} GOSUMDB=off GOFLAGS=-mod=mod

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w \
      -X github.com/hd25071/AgentGate/internal/version.Version=${VERSION}" \
      -o /out/agentgate ./cmd/agentgate && \
    go build -trimpath -ldflags "-s -w" -o /out/agentgate-cli ./cmd/agentgate-cli

# ---------------------------------------------------------------------------
FROM ${ALPINE_IMAGE:-alpine:3.20}

# The runtime image deliberately carries no shell tooling beyond busybox: the
# gateway's job is to be a narrow mediation point, and the image it ships in
# should not be a comfortable place to live after a compromise.
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S agentgate && \
    adduser -u 10001 -S agentgate -G agentgate && \
    mkdir -p /data && chown agentgate:agentgate /data

WORKDIR /app
COPY --from=build /out/agentgate /out/agentgate-cli /usr/local/bin/
COPY --from=build /src/policies /app/policies

USER 10001:10001

ENV AG_HTTP_ADDR=:8080 \
    AG_STORE_DRIVER=sqlite \
    AG_STORE_DSN="file:/data/agentgate.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" \
    AG_POLICY_DIR="" \
    AG_LOG_FORMAT=json

EXPOSE 8080

# busybox wget is enough for a liveness probe and adds no attack surface.
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=4 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/agentgate"]
CMD ["serve"]
