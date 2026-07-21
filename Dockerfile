FROM ctsrd/cheribsd-sdk-qemu-morello-purecap:latest

USER root

# The base image already contains make, ssh/scp, QEMU, and the Morello SDK.
# cheribuild still probes pkg-config for libarchive before run-morello-purecap;
# provide the minimal answer needed for that dependency check without requiring
# Ubuntu mirror access during image build.
RUN if ! command -v pkg-config >/dev/null 2>&1; then \
      printf '%s\n' \
        '#!/bin/sh' \
        'if [ "$1" = "--modversion" ] && [ "$2" = "libarchive" ]; then' \
        '  echo 3.0.0' \
        '  exit 0' \
        'fi' \
        'echo "pkg-config wrapper only supports --modversion libarchive" >&2' \
        'exit 1' > /usr/local/bin/pkg-config; \
      chmod +x /usr/local/bin/pkg-config; \
    fi

COPY tools/cheri_vm.py /usr/local/bin/cheri-vm
RUN chmod +x /usr/local/bin/cheri-vm

ENV WORKSPACE=/workspace
WORKDIR ${WORKSPACE}
