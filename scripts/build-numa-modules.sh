#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/lib/llvm-17/bin:$PATH"
test -f /artifacts/kernel-numa
test -f /work/out/vmlinux.symvers
test "$(cat /artifacts/build.status)" = completed
printf 'running\n' > /artifacts/vendor-build.status
mkdir -p /work/vendor-out /work/goldfish
if [[ ! -f /work/vendor-out/.config ]]; then
    cd /work/src
    KCONFIG_CONFIG=/work/vendor-out/.config scripts/kconfig/merge_config.sh -m \
        /work/out/.config /artifacts/virtual-device/virtual_device_core.fragment \
        /artifacts/virtual-device/virtual_device.fragment
fi
make -C /work/src O=/work/vendor-out LLVM=1 LLVM_IAS=1 olddefconfig
make -C /work/src O=/work/vendor-out LLVM=1 LLVM_IAS=1 KBUILD_MIXED_TREE=/work/out -j2 modules 2>&1 | tee /artifacts/vendor-build.log
cp -r /artifacts/virtual-device/goldfish_drivers/. /work/goldfish/
cp -r /artifacts/virtual-device/uapi /work/goldfish/
cat > /work/goldfish/Makefile <<'EOF'
obj-m += goldfish_address_space.o goldfish_pipe.o goldfish_sync.o
goldfish_pipe-y := goldfish_pipe_base.o goldfish_pipe_v1.o goldfish_pipe_v2.o
ccflags-y += -I$(src)/uapi
EOF
make -C /work/src O=/work/vendor-out LLVM=1 LLVM_IAS=1 M=/work/goldfish -j2 modules 2>&1 | tee /artifacts/goldfish-build.log
mkdir -p /artifacts/modules
while IFS= read -r module; do
    destination=/artifacts/modules/$(basename "$module")
    llvm-strip --strip-debug -o "$destination" "$module"
done < <(find /work/vendor-out /work/goldfish -name '*.ko')
cp /work/vendor-out/Module.symvers /artifacts/vendor-Module.symvers
cp /work/goldfish/Module.symvers /artifacts/goldfish-Module.symvers
printf 'completed\n' > /artifacts/vendor-build.status
