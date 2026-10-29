#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
printf 'running\n' > /artifacts/build.status
if ! command -v clang-17 >/dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends clang-17 llvm-17 lld-17 make gcc libc6-dev bc bison flex libssl-dev libelf-dev dwarves python3 cpio xz-utils rsync ca-certificates
fi
export PATH="/usr/lib/llvm-17/bin:$PATH"
mkdir -p /work/src /work/out
if [[ ! -f /work/src/Makefile ]]; then
    tar -xzf /artifacts/source.tar.gz --strip-components=1 -C /work/src
fi
cd /work/src
if [[ ! -f /work/out/.config ]]; then
    cp /artifacts/base.config /work/out/.config
    scripts/config --file /work/out/.config --enable NUMA --enable X86_64_ACPI_NUMA
    # Retain the base release string; record the custom configuration and image hash separately.
    scripts/config --file /work/out/.config --disable LOCALVERSION_AUTO --set-str LOCALVERSION '-android14-4-00257-g7e35917775b8-ab9964412'
fi
make LLVM=1 LLVM_IAS=1 O=/work/out olddefconfig
scripts/diffconfig /artifacts/base.config /work/out/.config > /artifacts/config.diff
cp /work/out/.config /artifacts/numa.config
clang --version > /artifacts/compiler.txt
make -j4 LLVM=1 LLVM_IAS=1 O=/work/out bzImage modules 2>&1 | tee /artifacts/build.log
if grep -Eq 'version generation failed|has no CRC' /artifacts/build.log; then
    printf 'Kernel symbol version generation is incomplete.\n' >&2
    exit 1
fi
cp /work/out/arch/x86/boot/bzImage /artifacts/kernel-numa
cp /work/out/Module.symvers /artifacts/Module.symvers
find /work/out -name '*.ko' -printf '%P\n' > /artifacts/modules.list
tar -C /work/out -czf /artifacts/modules.tar.gz -T /artifacts/modules.list
sha256sum /artifacts/kernel-numa > /artifacts/kernel-numa.sha256
printf 'completed\n' > /artifacts/build.status
