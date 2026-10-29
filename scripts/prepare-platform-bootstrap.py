"""Prepare a root-owned userdebug backend in an isolated pinned ReZygisk checkout."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "b5aa415c2ce1161ab807578ce0414129fbfc6313"


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError(f"Expected one source anchor: {before[:90]!r}")
    return text.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = args.checkout.resolve()
    if root.name != "ReZygisk-platform":
        raise ValueError("Use the separate ReZygisk-platform prototype checkout")
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)
    if revision != COMMIT or status.strip():
        raise ValueError("The prototype must start from a clean pinned checkout")
    originals = {}
    files = {}

    def source(name):
        if name not in files:
            originals[name] = (root / name).read_text(encoding="utf-8")
            files[name] = originals[name]
        return files[name]

    def change(name, before, after):
        files[name] = replace_once(source(name), before, after)

    name = "zygiskd/src/root_impl/common.c"
    text = source(name)
    start = text.index("void root_impls_setup(void) {")
    end = text.index("\nvoid get_impl(", start)
    replacement = '''void root_impls_setup(void) {
  impl.impl = None;
  if (getuid() != 0 || geteuid() != 0) return;
  if (access("/system/bin/magisk", F_OK) == 0) return;

  int marker = open("/data/misc/device-lab/platform-bootstrap-enabled", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (marker < 0) return;
  struct stat info = { 0 };
  char value[64] = { 0 };
  bool trusted = fstat(marker, &info) == 0 && S_ISREG(info.st_mode) &&
                 info.st_uid == 0 && (info.st_mode & 0777) == 0600;
  ssize_t size = trusted ? read(marker, value, sizeof(value) - 1) : -1;
  close(marker);
  if (size != 23 || memcmp(value, "device-lab-platform-v1\\n", 23) != 0) return;

  int current = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  if (current < 0) return;
  char context[64] = { 0 };
  ssize_t count = read(current, context, sizeof(context) - 1);
  close(current);
  if (count <= 0) return;
  context[strcspn(context, "\\n")] = '\\0';
  if (strcmp(context, "u:r:su:s0") != 0) return;
  impl.impl = Platform;
  LOGI("Root-owned userdebug platform backend selected");
}
'''
    files[name] = text[:start] + replacement + text[end:]
    change(name, '#include <errno.h>', '#include <errno.h>\n#include <fcntl.h>')
    change("zygiskd/src/root_impl/common.h", "  APatch,\n  Magisk\n", "  APatch,\n  Magisk,\n  Platform\n")
    change("zygiskd/src/utils.c", "    case None: {\n      strcpy(output, \"None\");", "    case Platform: {\n      strcpy(output, \"Platform\");\n      break;\n    }\n    case None: {\n      strcpy(output, \"None\");")
    change("zygiskd/src/utils.c", '"u:object_r:zygisk_file:s0"', '"u:object_r:zygote_socket:s0"')
    change("zygiskd/src/constants.h", "  PROCESS_IS_MANAGER = (1u << 27),", "  PROCESS_ROOT_IS_PLATFORM = (1u << 26),\n  PROCESS_IS_MANAGER = (1u << 27),")
    name = "zygiskd/src/zygiskd.c"
    text = source(name)
    text = text.replace('case None: { break; }', 'case Platform: { flags |= PROCESS_ROOT_IS_PLATFORM; break; }\n          case None: { break; }')
    if text.count('case Platform:') != 2:
        raise ValueError("Expected both daemon root-info switches")
    text = replace_once(text,
        'if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;',
        'if (strcmp(entry->d_name, "device_lab_cpu") != 0) continue;')
    text = replace_once(text,
        '    uint8_t action8 = 0;',
        '''    struct ucred peer = { 0 };
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
        peer_size != sizeof(peer) || peer.uid != 0) {
      close(client_fd);
      continue;
    }
    uint8_t action8 = 0;''')
    text = text.replace('"/data/adb/modules/rezygisk/bin/zygiskd"', '"/data/misc/device-lab/bootstrap/bin/zygiskd"')
    text = text.replace('PATH_MODULES_DIR "/rezygisk/bin/zygiskd"', '"/data/misc/device-lab/bootstrap/bin/zygiskd"')
    files[name] = text
    files[name] = source(name).replace("/data/adb/modules", "/data/misc/device-lab/modules")
    change("zygiskd/src/zygiskd.c", '''static int create_daemon_socket(void) {
  set_socket_create_context("u:r:zygote:s0");

  return unix_listener_from_path(PATH_CP_NAME);
}''', '''static int create_daemon_socket(void) {
  set_socket_create_context("u:r:zygote:s0");
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  const char name[] = "device_lab_platform_" LP_SELECT("cp32.sock", "cp64.sock");
  memcpy(address.sun_path + 1, name, sizeof(name));
  socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + sizeof(name));
  if (bind(fd, (struct sockaddr *)&address, length) != 0 || listen(fd, 8) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}''')
    change("zygiskd/src/zygiskd.c", '#include <sys/socket.h>', '#include <sys/socket.h>\n#include <sys/un.h>\n#include <stddef.h>')
    change("loader/src/include/daemon.h", "  ROOT_IMPL_MAGISK\n", "  ROOT_IMPL_MAGISK,\n  ROOT_IMPL_PLATFORM\n")
    change("loader/src/injector/module.h", "  PROCESS_IS_MANAGER = (1u << 27),", "  PROCESS_ROOT_IS_PLATFORM = (1u << 26),\n  PROCESS_IS_MANAGER = (1u << 27),")
    change("loader/src/injector/module.h", "  PRIVATE_MASK = PROCESS_IS_FIRST_STARTED", "  PRIVATE_MASK = PROCESS_IS_FIRST_STARTED | PROCESS_ROOT_IS_PLATFORM")
    change("loader/src/injector/hook.c", "    case FORCE_DENYLIST_UNMOUNT: {\n      FLAG_SET", "    case FORCE_DENYLIST_UNMOUNT: {\n      /* The platform backend creates no root-provider mount overlays. */\n      if (g_ctx->info_flags & PROCESS_ROOT_IS_PLATFORM) break;\n      FLAG_SET")
    change("loader/src/common/daemon.c", "  if (flags & (1 << 28))", "  if (flags & (1 << 26)) info->root_impl = ROOT_IMPL_PLATFORM;\n  else if (flags & (1 << 28))")
    change("loader/src/common/daemon.c", '#include <string.h>', '#include <string.h>\n#include <stddef.h>')
    change("loader/src/common/daemon.c", '  strcpy(addr.sun_path, TMP_PATH "/" SOCKET_FILE_NAME);', '''  strcpy(addr.sun_path + 1, "device_lab_platform_" SOCKET_FILE_NAME);
  socklen_t address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                        1 + strlen(addr.sun_path + 1));''')
    change("loader/src/common/daemon.c", 'connect(fd, (struct sockaddr *)&addr, sizeof(addr))', 'connect(fd, (struct sockaddr *)&addr, address_length)')
    change("zygiskd/src/main.c", '#include <stdlib.h>', '#include <stdlib.h>\n#include <unistd.h>')
    change("zygiskd/src/main.c", '    else if (strcmp(argv[1], "version") == 0) {', '''    else if (strcmp(argv[1], "platform-check") == 0) {
      root_impls_setup();
      struct root_impl selected;
      get_impl(&selected);
      bool ready = selected.impl == Platform;
      printf("{\\"platform_backend_ready\\":%s,\\"uid\\":%u}\\n", ready ? "true" : "false", (unsigned)getuid());
      return ready ? 0 : 1;
    }

    else if (strcmp(argv[1], "version") == 0) {''')
    change("loader/src/ptracer/main.c", "      case ROOT_IMPL_NONE: {", "      case ROOT_IMPL_PLATFORM: {\n        printf(\"Root implementation: Platform\\n\");\n        break;\n      }\n      case ROOT_IMPL_NONE: {")
    for name in ("zygiskd/src/zygiskd.c", "loader/src/include/daemon.h", "loader/src/ptracer/monitor.c"):
        files[name] = source(name).replace("/data/adb/rezygisk", "/data/misc/device-lab/zygisk")
    name = "loader/src/ptracer/monitor.c"
    files[name] = source(name).replace("/data/adb/modules/rezygisk/module.prop", "/data/misc/device-lab/bootstrap/module.prop")
    change("loader/src/ptracer/ptracer.c", '"/data/adb/modules/rezygisk/lib"', '"/data/misc/device-lab/bootstrap/lib"')
    changes = {}
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8", newline="\n")
        changes[name] = {"before_sha256": hashlib.sha256(originals[name].encode()).hexdigest(),
                         "after_sha256": hashlib.sha256(text.encode()).hexdigest()}
    patch = subprocess.check_output(["git", "-C", str(root), "diff", "--no-ext-diff"], text=True)
    args.report.with_suffix(".patch").write_text(patch, encoding="utf-8")
    result = {"upstream_commit": COMMIT, "checkout": str(root), "changes": changes,
              "module_allowlist": ["device_lab_cpu"], "root_grants_to_application_uids": False,
              "root_peer_required": True, "stock_userdebug_su_context_required": True,
              "magisk_bootstrap_required": False, "runtime_verified": False}
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"modified_files": len(changes), "runtime_verified": False}))


if __name__ == "__main__":
    main()
