#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
directory=/data/misc/device-lab/bootstrap/tricky-candidate
cd "$directory"
exec /system/bin/app_process -Djava.class.path="$directory/classes.dex" "$directory" \
    --nice-name=DeviceLabAttestationCandidate io.github.beakthoven.TrickyStoreOSS.MainKt
