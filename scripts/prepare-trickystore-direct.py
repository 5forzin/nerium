"""Prepare an experimental target-open transport without changing the SELinux policy."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    args = parser.parse_args()
    repository = args.cache / "trickystore-oss"
    revision = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    if revision != "dda5277d10b948ba6bec362252ec41f8bbbd9f97":
        raise ValueError("Unexpected source revision")
    native = repository / "app/src/main/cpp"
    original = (native / "inject/main.cpp").read_text(encoding="utf-8")
    old = """    auto lib_fd_opt = transfer_fd_to_remote(pid, lib_path, current_regs, local_map, remote_map, &pending_signal);
    if (!lib_fd_opt) {
        LOGE("Failed to transfer library fd to remote process");
        return false;
    }
    int lib_fd = *lib_fd_opt;
"""
    new = """    auto open_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "open");
    const uintptr_t remote_path = push_string(pid, current_regs, lib_path);
    if (!open_addr || !remote_path) return false;
    std::vector<uintptr_t> open_args = {remote_path, O_RDONLY | O_CLOEXEC, 0};
    auto opened = remote_call(pid, current_regs, reinterpret_cast<uintptr_t>(open_addr),
                              reinterpret_cast<uintptr_t>(libc_return_addr), open_args, &pending_signal);
    if (!opened || *opened > INT_MAX) {
        LOGE("Target could not open the read-only laboratory library");
        return false;
    }
    int lib_fd = static_cast<int>(*opened);
"""
    if original.count(old) != 1:
        raise ValueError("The pinned transport block changed")
    output = args.cache / "injector-direct"
    output.mkdir()
    modified = original.replace(old, new)
    (output / "main.cpp").write_text(modified, encoding="utf-8")
    cmake = f"""cmake_minimum_required(VERSION 3.22)
project(device_lab_target_open LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
add_executable(inject-direct
    main.cpp
    "{(native / 'inject/utils.cpp').as_posix()}"
    "{(native / 'maps/maps.cpp').as_posix()}"
    "{(native / 'logging/logging.cpp').as_posix()}")
target_include_directories(inject-direct PRIVATE
    "{(native / 'inject').as_posix()}"
    "{(native / 'maps/include').as_posix()}"
    "{(native / 'logging/include').as_posix()}")
target_link_libraries(inject-direct PRIVATE log dl)
"""
    (output / "CMakeLists.txt").write_text(cmake, encoding="utf-8")
    shutil.copytree(args.cache / "candidate-aosp", args.cache / "candidate-direct")
    manifest = {
        "source_revision": revision,
        "original_injector_source_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "adapted_injector_source_sha256": hashlib.sha256(modified.encode()).hexdigest(),
        "transport": "Open the library in the target process instead of sending an FD from the root process.",
        "policy_changes_required": False,
        "library_path": "/dev/device-lab-attestation/libTrickyStoreOSS.so",
        "library_label": "u:object_r:system_lib_file:s0",
    }
    (output / "adaptation.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"source_directory": str(output), "policy_changes_required": False}))


if __name__ == "__main__":
    main()
