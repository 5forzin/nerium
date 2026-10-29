"""Patch the stopped v42 clone while preserving its partition layout and policy."""

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import threading
import time
import uuid
import zlib


PROJECT = Path(__file__).resolve().parent.parent
LOCAL = Path(os.environ["LOCALAPPDATA"]) / "android-device-lab"
RUNTIME = PROJECT / ".local/keymint-v42"
RAW_SOURCE = LOCAL / "research-v14/vendor-platform-partition.img"
ELF_SOURCE = LOCAL / "research-v42/deploy/androidlab-keymint-service"
TOOLS = LOCAL / "research-v42/portable-e2fs/root/usr"
RECEIPT = PROJECT / "reports/keymint-v42-vendor-patch.json"
RAW_SHA = "5814211774f080825f110f6813d0292f9c8a9c526f6e865f8605b31e4dcf7c49"
ELF_SHA = "e2d73a9ae6765f91f107b031ac55c7667b089c9b1c113cb147b2ad9d3877a922"
IMAGE_SHA = {
    "system.img": "4806fbc745cd9abbfacc358496508f0ce420010e0ddaccef11e52e5da8e92f0a",
    "vendor.img": "30b356018896249d981d4bd7e3648bf0f6cf6cab8abf5e2aa52b037f1aaa1d9d",
}
RAW_SIZE = 100843520
SYSTEM_OFFSET = 3001024512
VENDOR_OFFSET = 1048576
SERVICE = "/bin/hw/android.hardware.security.keymint-service"
RC = "/etc/init/android.hardware.security.keymint-service.rc"
NEW_RC = (
    "service vendor.keymint-default /vendor/bin/hw/android.hardware.security.keymint-service /dev/vport22p1\n"
    "    class early_hal\n"
    "    user nobody\n"
).encode()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha_stream(stream, offset=0, length=None):
    stream.seek(offset)
    result = hashlib.sha256()
    remaining = length
    while remaining is None or remaining:
        chunk = stream.read(1024 * 1024 if remaining is None else min(remaining, 1024 * 1024))
        if not chunk:
            require(remaining is None, "Truncated image range")
            break
        result.update(chunk)
        if remaining is not None:
            remaining -= len(chunk)
    return result.hexdigest()


def sha(path):
    with path.open("rb") as stream:
        return sha_stream(stream)


def run(arguments, environment, events, allowed=(0,), timeout=180):
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}

    def drain(name, stream):
        with stream:
            while chunk := stream.read(8192):
                totals[name] += len(chunk)
                captured[name].extend(chunk[: max(0, 32768 - len(captured[name]))])

    workers = [threading.Thread(target=drain, args=(name, pipe)) for name, pipe in
               (("stdout", process.stdout), ("stderr", process.stderr))]
    for worker in workers:
        worker.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    for worker in workers:
        worker.join()
    event = {"arguments": list(map(str, arguments)), "exit_code": process.returncode,
             "timed_out": timed_out, "output_bytes": totals}
    event.update({name: bytes(value).decode("utf-8", errors="replace") for name, value in captured.items()})
    events.append(event)
    require(not timed_out and process.returncode in allowed, "Tool failed: " + str(arguments[0]))
    return event["stdout"]


def stopped(environment, events):
    shell = shutil.which("pwsh") or shutil.which("powershell.exe")
    require(shell is not None, "PowerShell is required for the process ownership check")
    command = """
$ErrorActionPreference='Stop'
$p=@(Get-CimInstance Win32_Process -Filter "Name='qemu-system-x86_64.exe' OR Name='qemu-system-x86_64-headless.exe'")
if (@($p | Where-Object { -not $_.CommandLine }).Count) { throw 'Cannot inspect all QEMU command lines' }
$owned=@($p | Where-Object { $_.CommandLine -match 'keymint-v42' } | Select-Object ProcessId,CommandLine)
ConvertTo-Json -InputObject $owned -Compress
"""
    output = run([shell, "-NoProfile", "-NonInteractive", "-Command", command], environment, events)
    require(json.loads(output.strip() or "[]") == [], "The owned v42 emulator is still running")


def quoted(value):
    value = str(value).replace("\\", "/")
    require(not any(c in value for c in '\"\r\n'), "Unsupported debugfs path")
    return '"' + value + '"'


class Ext4:
    def __init__(self, image, environment, events, work):
        self.image, self.environment, self.events, self.work = image, environment, events, work
        self.counter = 0

    def command(self, command, write=False):
        arguments = [str(TOOLS / "sbin/debugfs.exe")]
        if write:
            arguments.append("-w")
        return run(arguments + ["-R", command, str(self.image)], self.environment, self.events)

    def write_file(self, path, source):
        self.counter += 1
        commands = self.work / f"debugfs-write-{self.counter:05d}.txt"
        # debugfs 1.44.5 links the destination literally in cwd, including slashes.
        # Change directories and pass only a basename in the same process.
        commands.write_text(f"cd {quoted(Path(path).parent)}\nwrite {quoted(source)} {quoted(Path(path).name)}\n",
                            encoding="utf-8", newline="\n")
        run([str(TOOLS / "sbin/debugfs.exe"), "-w", "-f", str(commands), str(self.image)],
            self.environment, self.events)
        self.attributes(path)

    def dump(self, path, destination):
        self.command(f"dump {quoted(path)} {quoted(destination)}")
        require(destination.is_file(), "debugfs did not dump " + path)

    def attributes(self, path):
        stat = self.command("stat " + quoted(path))
        mode = re.search(r"Mode:\s+([0-7]+)", stat)
        owner = re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", stat)
        require(mode and owner, "Could not read inode attributes for " + path)
        listing = self.command("ea_list " + quoted(path))
        xattrs = {}
        for name, size in re.findall(r"^\s+(\S+)\s+\((\d+)\)\s*=", listing, re.M):
            self.counter += 1
            output = self.work / f"ea-{self.counter:05d}.bin"
            self.command(f"ea_get -f {quoted(output)} {quoted(path)} {quoted(name)}")
            require(output.is_file() and output.stat().st_size == int(size), "Incomplete EA extraction")
            xattrs[name] = {"sha256": sha(output), "bytes": int(size), "file": str(output)}
        return {"mode": mode.group(1), "uid": int(owner.group(1)), "gid": int(owner.group(2)), "xattrs": xattrs}

    def policy_snapshot(self, destination):
        destination.mkdir()
        self.command(f"rdump /etc/selinux {quoted(destination)}")
        contents = {str(p.relative_to(destination)).replace("\\", "/"): sha(p)
                    for p in destination.rglob("*") if p.is_file()}
        require(contents, "No SELinux policy files were extracted")
        attributes, pending = {}, ["/etc/selinux"]
        while pending:
            path = pending.pop()
            attributes[path] = self.attributes(path)
            listing = self.command("ls -p " + quoted(path))
            for line in listing.splitlines():
                fields = line.split("/")
                if not line.startswith("/") or len(fields) < 7 or fields[5] in (".", ".."):
                    continue
                child = path + "/" + fields[5]
                mode = int(fields[2], 8)
                if mode & 0o170000 == 0o040000:
                    pending.append(child)
                else:
                    attributes[child] = self.attributes(child)
        return {"files": contents, "attributes": semantic_attributes(attributes)}

    def replace(self, path, source, attributes, expected_mode=None):
        self.command("rm " + quoted(path), write=True)
        self.write_file(path, source)
        mode = expected_mode or ("0" + format(0o100000 | int(attributes["mode"], 8), "o"))
        for field, value in (("mode", mode), ("uid", attributes["uid"]), ("gid", attributes["gid"])):
            self.command(f"set_inode_field {quoted(path)} {field} {value}", write=True)
        for name, value in attributes["xattrs"].items():
            self.command(f"ea_set -f {quoted(value['file'])} {quoted(path)} {quoted(name)}", write=True)
        after = self.attributes(path)
        require(semantic_attributes({path: after}) == semantic_attributes({path: attributes}),
                "Replacement inode attributes changed: " + path)
        for name, value in attributes["xattrs"].items():
            require(Path(after["xattrs"][name]["file"]).read_bytes() == Path(value["file"]).read_bytes(),
                    "Replacement EA bytes changed: " + path + ":" + name)
        output = self.work / ("verified-" + Path(path).name)
        self.dump(path, output)
        require(sha(output) == sha(source), "Replacement content verification failed: " + path)
        return {"sha256": sha(output), "bytes": output.stat().st_size,
                "attributes": semantic_attributes({path: after})[path]}


def semantic_attributes(attributes):
    return {path: {**value, "xattrs": {name: {k: v for k, v in ea.items() if k != "file"}
                  for name, ea in value["xattrs"].items()}} for path, value in attributes.items()}


def image_metadata(stream, system):
    def gpt(offset):
        stream.seek(offset)
        raw = stream.read(512)
        require(raw[:8] == b"EFI PART", "GPT signature mismatch")
        size, checksum = struct.unpack_from("<II", raw, 12)
        require(92 <= size <= 512, "Invalid GPT header size")
        checked = bytearray(raw[:size]); checked[16:20] = bytes(4)
        require(zlib.crc32(checked) == checksum, "GPT header CRC mismatch")
        table, count, entry_size, crc = struct.unpack_from("<QIII", raw, 72)
        require(count <= 128 and entry_size == 128, "Unexpected GPT table shape")
        stream.seek(table * 512)
        entries = stream.read(count * entry_size)
        require(zlib.crc32(entries) == crc, "GPT table CRC mismatch")
        parts = {}
        for i in range(count):
            entry = entries[i * entry_size:(i + 1) * entry_size]
            if any(entry[:16]):
                start, end = struct.unpack_from("<QQ", entry, 32)
                parts[entry[56:128].decode("utf-16-le").rstrip("\0")] = (start * 512, (end + 1) * 512)
        return {"header_sha256": hashlib.sha256(raw).hexdigest(),
                "table_sha256": hashlib.sha256(entries).hexdigest(), "partitions": parts}, struct.unpack_from("<Q", raw, 32)[0]

    primary, backup_lba = gpt(512)
    backup, _ = gpt(backup_lba * 512)
    require(primary["partitions"] == backup["partitions"], "GPT copies disagree")
    result = {"primary_gpt": primary, "backup_gpt": backup}
    if not system:
        start, end = primary["partitions"]["vendor"]
        require(start == VENDOR_OFFSET and end >= start + RAW_SIZE, "Unexpected external vendor bounds")
        return result
    start, end = primary["partitions"]["super"]
    require(start <= SYSTEM_OFFSET and SYSTEM_OFFSET + RAW_SIZE <= end, "Vendor exceeds super bounds")
    geometries = []
    for relative in (4096, 8192):
        stream.seek(start + relative); raw = stream.read(4096)
        magic, size = struct.unpack_from("<II", raw)
        require(magic == 0x616C4467 and size == 52, "Unexpected LP geometry")
        checked = bytearray(raw[:size]); checked[8:40] = bytes(32)
        require(hashlib.sha256(checked).digest() == raw[8:40], "LP geometry checksum mismatch")
        geometries.append(hashlib.sha256(raw).hexdigest())
    require(geometries[0] == geometries[1], "LP geometry copies disagree")
    maximum, slots = struct.unpack_from("<II", raw, 40)
    require(maximum == 65536 and slots == 2, "Unexpected LP slot layout")
    copies = []
    for i in range(slots * 2):
        position = start + 12288 + maximum * i
        stream.seek(position); raw = stream.read(maximum)
        require(raw[:4] == b"0PLA", "Invalid LP header")
        header_size, = struct.unpack_from("<I", raw, 8)
        table_size, = struct.unpack_from("<I", raw, 44)
        require(128 <= header_size <= 256 and header_size + table_size <= maximum, "Invalid LP table bounds")
        checked = bytearray(raw[:header_size]); checked[12:44] = bytes(32)
        tables = raw[header_size:header_size + table_size]
        require(hashlib.sha256(checked).digest() == raw[12:44], "LP header checksum mismatch")
        require(hashlib.sha256(tables).digest() == raw[48:80], "LP table checksum mismatch")
        po, pn, ps = struct.unpack_from("<III", raw, 80)
        eo, en, es = struct.unpack_from("<III", raw, 92)
        require(ps == 52 and es == 24 and po + pn * ps <= len(tables) and eo + en * es <= len(tables), "Invalid LP descriptors")
        vendors = []
        for n in range(pn):
            entry = tables[po + n * ps:po + (n + 1) * ps]
            if entry[:36].rstrip(b"\0") == b"vendor":
                _, first, count, _ = struct.unpack_from("<IIII", entry, 36)
                require(count == 1 and first < en, "Expected one vendor extent")
                sectors, target, sector, device = struct.unpack_from("<QIQI", tables, eo + first * es)
                require(target == 0 and device == 0, "Unexpected vendor mapping")
                vendors.append((start + sector * 512, sectors * 512))
        require(vendors == [(SYSTEM_OFFSET, RAW_SIZE)], "Embedded vendor mapping mismatch")
        copies.append({"offset": position, "sha256": hashlib.sha256(raw).hexdigest()})
    require(len({item["sha256"] for item in copies}) == 1, "LP metadata copies disagree")
    return {**result, "geometry_sha256": geometries, "lp_copies": copies}


@contextlib.contextmanager
def exclusive_image(path):
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create.restype = ctypes.c_void_p
    handle = create(str(path), 0xC0000000, 0, None, 3, 0x80, None)
    require(handle != ctypes.c_void_p(-1).value, "Cannot exclusively lock clone image: " + str(path))
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(descriptor, "r+b", buffering=0) as stream:
        yield stream


def copy_extent(stream, offset, source):
    stream.seek(offset)
    with source.open("rb") as payload:
        shutil.copyfileobj(payload, stream, 1024 * 1024)
    stream.flush()
    os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Apply to the stopped isolated v42 clone")
    arguments = parser.parse_args()
    require(arguments.apply, "Execution requires --apply after review and stopping the isolated clone")
    receipt = {"schema_version": 1, "status": "running", "phase": "preflight", "tools": [],
               "runtime": str(RUNTIME), "original_images_modified": False,
               "patcher_sha256": sha(Path(__file__).resolve()),
               "avb": {"original_hashtree_verification": "known_failing_before_patch",
                       "descriptor_algorithm": "NONE", "original_fec_roots": 2,
                       "regenerated": False, "verified_boot_claim": False,
                       "limitation": "The existing AVB hashtree is already invalid. This patch does not repair it or establish verified boot."}}
    environment = os.environ.copy()
    environment["PATH"] = str(TOOLS / "bin") + os.pathsep + str(TOOLS / "sbin") + os.pathsep + environment.get("PATH", "")
    work = None
    try:
        require(os.name == "nt", "This patcher requires Windows")
        require(RUNTIME.resolve().parent == (PROJECT / ".local").resolve(), "Unexpected runtime location")
        manifest = json.loads((RUNTIME / "clone-manifest.json").read_text(encoding="utf-8-sig"))
        require(manifest["state"] == "prepared" and Path(manifest["runtime"]).resolve() == RUNTIME.resolve(), "Clone manifest is not prepared")
        stopped(environment, receipt["tools"])
        require(RAW_SOURCE.stat().st_size == RAW_SIZE and sha(RAW_SOURCE) == RAW_SHA, "Original vendor raw differs")
        require(ELF_SOURCE.stat().st_size == 589192 and sha(ELF_SOURCE) == ELF_SHA, "Candidate ELF differs")
        with ELF_SOURCE.open("rb") as stream:
            header = stream.read(64)
        require(header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62, "Candidate must be x86_64 ELF")
        targets = [(RUNTIME / "system-images/system.img", SYSTEM_OFFSET),
                   (RUNTIME / "system-images/vendor.img", VENDOR_OFFSET)]
        receipt["before"] = {}
        for path, offset in targets:
            require(path.resolve().parent == (RUNTIME / "system-images").resolve(), "Target escapes clone")
            source_image = Path(manifest["source_images"]) / path.name
            require(not os.path.samefile(path, source_image), "Clone is a hard link to an original image")
            require(manifest["files"]["system-images/" + path.name] == IMAGE_SHA[path.name], "Manifest image hash differs")
            with path.open("rb") as stream:
                require(path.stat().st_size >= offset + RAW_SIZE, "Image extent exceeds file bounds")
                require(sha_stream(stream) == IMAGE_SHA[path.name], "Clone whole image differs from baseline")
                require(sha_stream(stream, offset, RAW_SIZE) == RAW_SHA, "Clone vendor extent differs from rollback source")
                receipt["before"][path.name] = {"sha256": IMAGE_SHA[path.name], "bytes": path.stat().st_size,
                    "metadata": image_metadata(stream, path.name == "system.img"),
                    "prefix_sha256": sha_stream(stream, 0, offset),
                    "suffix_sha256": sha_stream(stream, offset + RAW_SIZE)}
        stopped(environment, receipt["tools"])
        work = LOCAL / "research-v42/vendor-patch" / (time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])
        work.mkdir(parents=True)
        rollback, image = work / "rollback-vendor.img", work / "candidate-vendor.img"
        shutil.copyfile(RAW_SOURCE, rollback)
        require(sha(rollback) == RAW_SHA, "Rollback raw verification failed")
        receipt["rollback_raw"] = str(rollback)
        shutil.copyfile(rollback, image)
        staged_elf = work / "candidate-keymint-service"
        shutil.copyfile(ELF_SOURCE, staged_elf)
        require(sha(staged_elf) == ELF_SHA, "Candidate ELF changed during staging")
        ext4 = Ext4(image, environment, receipt["tools"], work)
        before_policy = ext4.policy_snapshot(work / "policy-before")
        service_attrs, rc_attrs = ext4.attributes(SERVICE), ext4.attributes(RC)
        require(service_attrs["mode"] == "0755" and service_attrs["uid"] == 0 and service_attrs["gid"] == 2000, "Original HAL inode differs")
        label = service_attrs["xattrs"].get("security.selinux")
        require(label and Path(label["file"]).read_bytes() == b"u:object_r:hal_keymint_default_exec:s0\0", "Original HAL label differs")
        old_rc = work / "original-service.rc"; ext4.dump(RC, old_rc)
        require(old_rc.read_bytes() == NEW_RC.replace(b" /dev/vport22p1", b""), "Original init service differs")
        new_rc = work / "candidate-service.rc"; new_rc.write_bytes(NEW_RC)
        with rollback.open("rb") as stream:
            stream.seek(-64, 2); footer = stream.read(64)
        magic, major, minor, filesystem_size, vbmeta_offset, vbmeta_size, _ = struct.unpack(">4sIIQQQ28s", footer)
        require(magic == b"AVBf" and filesystem_size == 99164160, "Unexpected original AVB trailer")
        receipt["avb"]["footer"] = {"major": major, "minor": minor, "filesystem_size": filesystem_size,
                                    "vbmeta_offset": vbmeta_offset, "vbmeta_size": vbmeta_size}
        with rollback.open("rb") as stream:
            trailer_sha = sha_stream(stream, filesystem_size)
        receipt["phase"] = "prepare_private_vendor"
        run([str(TOOLS / "sbin/e2fsck.exe"), "-fy", "-E", "unshare_blocks", str(image)], environment, receipt["tools"], allowed=(0, 1))
        stats = ext4.command("stats")
        features = re.search(r"Filesystem features:(.*?)(?:\nFilesystem flags:|\nDefault mount options:|\nFilesystem state:)", stats, re.S)
        require(features and "shared_blocks" not in features.group(1), "Filesystem still has shared blocks")
        receipt["binary"] = ext4.replace(SERVICE, staged_elf, service_attrs, expected_mode="0100755")
        receipt["init_rc"] = ext4.replace(RC, new_rc, rc_attrs)
        after_policy = ext4.policy_snapshot(work / "policy-after")
        require(before_policy == after_policy, "SELinux policy contents or inode attributes changed")
        receipt["selinux_policy"] = {"unchanged": True, **after_policy}
        run([str(TOOLS / "sbin/e2fsck.exe"), "-fn", str(image)], environment, receipt["tools"])
        with image.open("rb") as stream:
            require(sha_stream(stream, filesystem_size) == trailer_sha, "AVB trailer changed")
        require(image.stat().st_size == RAW_SIZE, "Vendor raw size changed")
        patched_sha = sha(image)
        receipt.update({"patched_raw": str(image), "patched_raw_sha256": patched_sha, "avb_trailer_unchanged": True})
        receipt["phase"] = "commit_clone_extents"
        stopped(environment, receipt["tools"])
        with contextlib.ExitStack() as stack:
            handles = [(path, offset, stack.enter_context(exclusive_image(path))) for path, offset in targets]
            for path, offset, stream in handles:
                require(sha_stream(stream) == IMAGE_SHA[path.name], "Clone changed during preparation")
            touched = []
            try:
                for path, offset, stream in handles:
                    touched.append((path, offset, stream))
                    copy_extent(stream, offset, image)
                    require(sha_stream(stream, offset, RAW_SIZE) == patched_sha, "Committed extent verification failed")
                receipt["after"] = {}
                for path, offset, stream in handles:
                    before = receipt["before"][path.name]
                    require(os.fstat(stream.fileno()).st_size == before["bytes"], "Clone image size changed")
                    require(image_metadata(stream, path.name == "system.img") == before["metadata"], "GPT or LP metadata changed")
                    require(sha_stream(stream, 0, offset) == before["prefix_sha256"] and
                            sha_stream(stream, offset + RAW_SIZE) == before["suffix_sha256"], "Bytes outside vendor extent changed")
                    receipt["after"][path.name] = {"sha256": sha_stream(stream), "extent_sha256": patched_sha,
                        "offset": offset, "length": RAW_SIZE, "outside_extent_unchanged": True, "metadata_unchanged": True}
            except BaseException:
                receipt["automatic_rollback"] = {}
                for path, offset, stream in touched:
                    try:
                        copy_extent(stream, offset, rollback)
                        receipt["automatic_rollback"][path.name] = sha_stream(stream) == IMAGE_SHA[path.name]
                    except Exception as error:
                        receipt["automatic_rollback"][path.name] = {"error": str(error)}
                raise
        receipt.update({"status": "passed", "phase": "complete", "fsck": "passed",
                        "gpt_lp_unchanged": True, "vendor_extents_identical": True})
    except BaseException as error:
        receipt.update({"status": "failed", "error": str(error), "error_type": type(error).__name__})
        raise
    finally:
        receipt["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        RECEIPT.parent.mkdir(exist_ok=True)
        RECEIPT.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "receipt": str(RECEIPT), "rollback": receipt["rollback_raw"]}))


if __name__ == "__main__":
    main()
