# libbpf-devel isn't packaged in RHEL 9.1
FROM registry.fedoraproject.org/fedora:37 as build-bpf
RUN dnf install -qy \
    libbpf-devel \
    make \
    clang \
    llvm \
    bpftool \
    kernel-headers
WORKDIR /src
COPY . .
RUN make mallocsnoop

# Build golang-based exporter binary
FROM docker.io/library/golang:1.19 as build-go
WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build ./...

# Package both binaries in a single UBI image
FROM registry.access.redhat.com/ubi9/ubi:9.1.0
COPY --from=build-bpf /src/mallocsnoop mallocsnoop
COPY --from=build-go /src/exporter exporter
ENTRYPOINT /exporter
