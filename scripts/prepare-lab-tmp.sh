#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop ro.kernel.qemu)" = 1 ] || exit 1
[ "$(stat -c %d /data/local)" = 65064 ] || exit 1
stage=/data/local/device-lab-tmp-v12
[ ! -e "$stage" ] || exit 1
allocator=/sys/fs/ext4/dm-40/inode_goal
previous=$(cat "$allocator")
[ "$previous" = 0 ] || exit 1
write_goal() {
    echo "$1" | dd of="$allocator" bs=4096 2>/dev/null
}
trap 'write_goal "$previous"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
write_goal 1000
mkdir -m 0700 "$stage"
write_goal "$previous"
trap - EXIT
inode=$(stat -c %i "$stage")
if [ "$inode" -ge 10000 ]; then
    rmdir "$stage"
    echo 'The allocator did not supply a low inode.' >&2
    exit 2
fi
printf '{"stage_inode":%s,"allocator_goal_before":%s,"allocator_goal_after":%s}\n' "$inode" "$previous" "$(cat "$allocator")"
