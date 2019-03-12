FROM golang:1.10-alpine as rev-builder
LABEL org.label-schema.name="revDNS" \
      org.label-schema.description="revDNS" \
      org.label-schema.build-date="${build_date}"
RUN apk add --no-cache git make ca-certificates wget build-base
RUN wget -q -O /go/bin/dep https://github.com/golang/dep/releases/download/v0.3.2/dep-linux-amd64 && chmod +x /go/bin/dep
WORKDIR /go/src/github.com/gviz/revDNS
COPY . .

# Change ARGs with --build-arg to target other architectures
# Produce a self-contained statically linked binary
ARG CGO_ENABLED=0
# Set the build target architecture and OS
ARG GOARCH=amd64
ARG GOOS=linux
# Passing arguments in to make result in them being set as 
# environment variables for the call to go build
RUN env CGO_ENABLED=$CGO_ENABLED GOARCH=$GOARCH GOOS=$GOOS go build .

FROM scratch

WORKDIR /
COPY --from=rev-builder /go/src/github.com/gviz/revDNS/revdns.yaml /revdns.yaml
COPY --from=rev-builder /go/src/github.com/gviz/revDNS/revDNS /revDNS
EXPOSE 9090/tcp
ENTRYPOINT ["/revDNS"]
