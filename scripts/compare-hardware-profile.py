"""Diff two hardware snapshots produced by capture-hardware.ps1.

Typical use: a physical reference captured on a rented Firebase device against
the same collector run on the emulator with the profile enabled. Every section
prints matches, differences and one-sided entries; an entry present on only one
side is exactly the to-do list for the next profile revision.

Usage:
    python compare-hardware-profile.py PHYSICAL.json EMULATOR.json [--output diff.json]
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Properties detectors actually read. The full key-set diff below catches the rest.
TRACKED_PROPERTIES = [
    "ro.product.manufacturer", "ro.product.brand", "ro.product.model",
    "ro.product.device", "ro.product.name", "ro.product.board",
    "ro.product.cpu.abilist", "ro.product.cpu.abilist64", "ro.product.cpu.abilist32",
    "ro.hardware", "ro.boot.hardware", "ro.boot.hardware.sku",
    "ro.kernel.qemu", "ro.kernel.qemu.gles", "ro.boot.qemu",
    "ro.boot.qemu.avd_name", "ro.bootimage.build.fingerprint",
    "ro.build.fingerprint", "ro.build.id", "ro.build.type", "ro.build.tags",
    "ro.build.version.incremental", "ro.build.flavor",
    "ro.board.platform", "ro.soc.manufacturer", "ro.soc.model",
    "ro.hardware.egl", "ro.hardware.vulkan", "ro.opengles.version",
    "ro.dalvik.vm.native.bridge", "ro.dalvik.vm.isa.arm", "ro.dalvik.vm.isa.arm64",
    "ro.boot.flash.locked", "ro.boot.verifiedbootstate", "ro.boot.veritymode",
    "ro.boot.bootdevices", "ro.boot.bootdevice", "ro.hardware.audio.primary",
]

SENSOR_TYPE_LABEL = {
    "android.sensor.accelerometer": "accelerometer",
    "android.sensor.gyroscope": "gyroscope",
    "android.sensor.magnetic_field": "magnetometer",
    "android.sensor.light": "light",
    "android.sensor.proximity": "proximity",
    "android.sensor.pressure": "barometer",
}


def load(path):
    # Windows PowerShell writes a UTF-8 BOM; utf-8-sig tolerates both.
    with open(path, encoding="utf-8-sig") as handle:
        return json.load(handle)


def app_section(snapshot, name):
    """Return an app section, or None when it failed to collect."""
    section = snapshot.get("app", {}).get(name)
    if not isinstance(section, dict) or "error" in section:
        return None
    return section


def line(label, reference, candidate):
    if reference == candidate:
        print(f"  ok    {label}: {reference}")
        return 0
    print(f"  DIFF  {label}:\n        physical : {reference}\n        other    : {candidate}")
    return 1


def compare_identity(a, b):
    print("identity (Build/getprop level)")
    identity_a = a.get("identity", {})
    identity_b = b.get("identity", {})
    differences = 0
    for key in ("manufacturer", "brand", "model", "device", "product", "board",
                "hardware", "bootloader", "radio", "fingerprint", "build_id",
                "build_type", "build_tags", "security_patch", "release", "sdk", "abis"):
        differences += line(key, identity_a.get(key), identity_b.get(key))
    return differences


def compare_properties(a, b):
    print("system properties (detector-relevant subset)")
    values_a = app_section(a, "properties")
    values_b = app_section(b, "properties")
    if values_a is None or values_b is None:
        print("  unavailable on at least one side")
        return 0
    map_a = values_a.get("values", {})
    map_b = values_b.get("values", {})
    differences = 0
    for key in TRACKED_PROPERTIES:
        if key in map_a or key in map_b:
            differences += line(key, map_a.get(key), map_b.get(key))
    only_a = sorted(set(map_a) - set(map_b))
    only_b = sorted(set(map_b) - set(map_a))
    if only_a:
        print(f"  keys only on physical side ({len(only_a)}): {', '.join(only_a[:20])}"
              + (" ..." if len(only_a) > 20 else ""))
        differences += len(only_a)
    if only_b:
        print(f"  keys only on other side ({len(only_b)}): {', '.join(only_b[:20])}"
              + (" ..." if len(only_b) > 20 else ""))
        differences += len(only_b)
    return differences


def parse_cpuinfo(raw):
    """Return {field: value-or-set} for the first core plus the core count."""
    cores = 0
    fields = {}
    for block in re.split(r"\n\s*\n", raw.strip()):
        if not block.strip():
            continue
        if re.search(r"^processor\s*:", block, re.MULTILINE):
            cores += 1
        for entry in block.splitlines():
            match = re.match(r"([^:]+?)\s*:\s*(.*)", entry)
            if not match:
                continue
            key, value = match.group(1).strip(), match.group(2).strip()
            if key in ("processor",):
                continue
            if key == "Features":
                fields.setdefault(key, set()).update(value.split())
            else:
                fields.setdefault(key, set()).add(value)
    return cores, {key: value for key, value in fields.items()}


def compare_cpuinfo(a, b):
    print("kernel /proc/cpuinfo")
    raw_a = app_section(a, "kernel")
    raw_b = app_section(b, "kernel")
    if raw_a is None or raw_b is None:
        print("  unavailable on at least one side")
        return 0
    cores_a, fields_a = parse_cpuinfo(raw_a.get("cpuinfo", ""))
    cores_b, fields_b = parse_cpuinfo(raw_b.get("cpuinfo", ""))
    differences = line("online processor records", cores_a, cores_b)
    for key in sorted(set(fields_a) | set(fields_b)):
        value_a = fields_a.get(key)
        value_b = fields_b.get(key)
        differences += line(key,
                            sorted(value_a) if value_a is not None else None,
                            sorted(value_b) if value_b is not None else None)
    return differences


def compare_sensors(a, b):
    print("sensor labels")
    sensors_a = app_section(a, "sensors")
    sensors_b = app_section(b, "sensors")
    if sensors_a is None or sensors_b is None:
        print("  unavailable on at least one side")
        return 0
    by_type_a = {}
    by_type_b = {}
    for item in sensors_a.get("list", []):
        by_type_a.setdefault(item.get("string_type"), []).append(item.get("name"))
    for item in sensors_b.get("list", []):
        by_type_b.setdefault(item.get("string_type"), []).append(item.get("name"))
    differences = 0
    for sensor_type in sorted(set(by_type_a) | set(by_type_b)):
        names_a = sorted(by_type_a.get(sensor_type) or [])
        names_b = sorted(by_type_b.get(sensor_type) or [])
        label = SENSOR_TYPE_LABEL.get(sensor_type, sensor_type)
        if names_a == names_b:
            print(f"  ok    {label}: {names_a}")
        else:
            print(f"  DIFF  {label}:\n        physical : {names_a}\n        other    : {names_b}")
            differences += 1
    return differences


def compare_graphics(a, b):
    print("graphics strings")
    graphics_a = app_section(a, "graphics")
    graphics_b = app_section(b, "graphics")
    if graphics_a is None or graphics_b is None:
        print("  unavailable on at least one side")
        return 0
    differences = 0
    for key in ("egl_vendor", "egl_version", "gles_vendor", "gles_renderer",
                "gles_version", "gles_shading_language"):
        differences += line(key, graphics_a.get(key), graphics_b.get(key))
    extensions_a = set((graphics_a.get("gles_extensions") or "").split())
    extensions_b = set((graphics_b.get("gles_extensions") or "").split())
    missing = sorted(extensions_a - extensions_b)
    extra = sorted(extensions_b - extensions_a)
    if missing:
        print(f"  extensions missing on other side ({len(missing)}): {' '.join(missing[:12])}")
    if extra:
        print(f"  extensions only on other side ({len(extra)}): {' '.join(extra[:12])}")
    return differences + len(missing) + len(extra)


def compare_cameras(a, b):
    print("cameras")
    cameras_a = app_section(a, "cameras")
    cameras_b = app_section(b, "cameras")
    if cameras_a is None or cameras_b is None:
        print("  unavailable on at least one side")
        return 0
    differences = line("camera count", cameras_a.get("count"), cameras_b.get("count"))
    for item_a, item_b in zip(cameras_a.get("list", []), cameras_b.get("list", [])):
        differences += line(f"camera {item_a.get('id')} facing",
                            item_a.get("facing"), item_b.get("facing"))
        differences += line(f"camera {item_a.get('id')} pixel array",
                            item_a.get("sensor_pixel_array"), item_b.get("sensor_pixel_array"))
        differences += line(f"camera {item_a.get('id')} hardware level",
                            item_a.get("hardware_level"), item_b.get("hardware_level"))
    return differences


def compare_sets(label, names_a, names_b, differences):
    only_a = sorted(set(names_a) - set(names_b))
    only_b = sorted(set(names_b) - set(names_a))
    if not only_a and not only_b and len(names_a) == len(names_b):
        print(f"  ok    {label}: {len(names_a)} entries match")
        return differences
    print(f"  DIFF  {label}: only physical ({len(only_a)}): {only_a[:15]}")
    print(f"        only other ({len(only_b)}): {only_b[:15]}")
    return differences + len(only_a) + len(only_b)


def compare_remaining(a, b):
    differences = 0
    print("system features")
    features_a = app_section(a, "features")
    features_b = app_section(b, "features")
    if features_a is not None and features_b is not None:
        differences = compare_sets("feature names",
                                   [f["name"] for f in features_a.get("list", [])],
                                   [f["name"] for f in features_b.get("list", [])], differences)
    else:
        print("  unavailable on at least one side")
    print("input devices")
    inputs_a = app_section(a, "input_devices")
    inputs_b = app_section(b, "input_devices")
    if inputs_a is not None and inputs_b is not None:
        differences = compare_sets("input device names",
                                   [d["name"] for d in inputs_a.get("list", [])],
                                   [d["name"] for d in inputs_b.get("list", [])], differences)
    else:
        print("  unavailable on at least one side")
    print("codecs")
    codecs_a = app_section(a, "codecs")
    codecs_b = app_section(b, "codecs")
    if codecs_a is not None and codecs_b is not None:
        differences = compare_sets("codec names",
                                   [c["name"] for c in codecs_a.get("list", [])],
                                   [c["name"] for c in codecs_b.get("list", [])], differences)
    else:
        print("  unavailable on at least one side")
    print("Widevine DRM")
    drm_a = app_section(a, "drm")
    drm_b = app_section(b, "drm")
    if drm_a is not None and drm_b is not None:
        differences += line("security level", drm_a.get("security_level"), drm_b.get("security_level"))
        differences += line("version", drm_a.get("version"), drm_b.get("version"))
    else:
        print("  unavailable on at least one side")
    print("memory")
    memory_a = app_section(a, "memory")
    memory_b = app_section(b, "memory")
    if memory_a is not None and memory_b is not None:
        print(f"        physical total {memory_a.get('total_mem')} vs other {memory_b.get('total_mem')}")
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("physical", help="snapshot captured on the physical reference device")
    parser.add_argument("candidate", help="snapshot captured on the emulator or second device")
    parser.add_argument("--output", help="also write the comparison as JSON")
    args = parser.parse_args()

    physical = load(args.physical)
    candidate = load(args.candidate)
    names = {
        "physical": Path(args.physical).stem,
        "candidate": Path(args.candidate).stem,
    }
    print(f"hardware profile diff: {names['physical']} (physical) vs {names['candidate']}")
    print(f"physical identity: {physical.get('identity', {}).get('model')} "
          f"api {physical.get('identity', {}).get('sdk')}")
    print(f"candidate identity: {candidate.get('identity', {}).get('model')} "
          f"api {candidate.get('identity', {}).get('sdk')}")
    print()

    totals = {}
    totals["identity"] = compare_identity(physical, candidate)
    print()
    totals["properties"] = compare_properties(physical, candidate)
    print()
    totals["cpuinfo"] = compare_cpuinfo(physical, candidate)
    print()
    totals["sensors"] = compare_sensors(physical, candidate)
    print()
    totals["graphics"] = compare_graphics(physical, candidate)
    print()
    totals["cameras"] = compare_cameras(physical, candidate)
    print()
    totals["remaining"] = compare_remaining(physical, candidate)

    print()
    print("differences by section:", json.dumps(totals))
    total = sum(totals.values())
    print(f"{total} total differences - each one is a candidate for the next profile revision.")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump({"names": names, "totals": totals, "total": total}, handle, indent=2)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
