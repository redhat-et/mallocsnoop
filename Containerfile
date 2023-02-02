# libbpf-devel isn't packaged in RHEL 9.1
FROM fedora:37 as base
RUN dnf install -qy \
    libbpf-devel \
    make \
    clang \
    llvm \
    bpftool \
    kernel-headers
WORKDIR /src
COPY . .
RUN make

FROM registry.access.redhat.com/ubi9/ubi:9.1.0
COPY --from=base /src/mallocsnoop mallocsnoop
ENTRYPOINT /mallocsnoop
