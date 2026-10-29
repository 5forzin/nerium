#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/lib/llvm-17/bin:$PATH"
printf 'running\n' > /artifacts/kernel-build.status
trap 'printf "failed\n" > /artifacts/kernel-build.status' ERR
test -f /baseline/src/kernel/seccomp.c
test -f /baseline/out/vmlinux.symvers
if [[ ! -f /work/baseline-cloned-v13 ]]; then
    cp -a /baseline/. /work/
    touch /work/baseline-cloned-v13
fi
python3 /artifacts/prepare-supervisor-kernel.py /baseline/src/kernel/seccomp.c \
    --output /work/src/kernel/seccomp.c \
    --patch /artifacts/seccomp-platform.patch \
    --report /artifacts/kernel-patch-proposal.json
clang --version > /artifacts/kernel-compiler.txt
cp /work/out/.config /artifacts/kernel-platform.config
make -C /work/src O=/work/out LLVM=1 LLVM_IAS=1 -j2 bzImage 2>&1 | tee /artifacts/kernel-build.log
python3 - <<'PY'
import json
from pathlib import Path
def exports(path):
    return {parts[1]:parts[0] for line in Path(path).read_text().splitlines() if len(parts := line.split()) >= 2}
before = exports('/baseline/out/vmlinux.symvers')
after = exports('/work/out/vmlinux.symvers')
changes = {name:{'before':before.get(name),'after':after.get(name)} for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
Path('/artifacts/kernel-export-comparison.json').write_text(json.dumps({'before':len(before),'after':len(after),'changes':changes},indent=2)+'\n')
if changes:
    raise SystemExit('Kernel export CRCs changed; inspect module compatibility before booting.')
PY
cp /work/out/arch/x86/boot/bzImage /artifacts/kernel-platform
sha256sum /artifacts/kernel-platform > /artifacts/kernel-platform.sha256
sha256sum /baseline/src/kernel/seccomp.c > /artifacts/baseline-source-after.sha256
printf 'completed\n' > /artifacts/kernel-build.status
