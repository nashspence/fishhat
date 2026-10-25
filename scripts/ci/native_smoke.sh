#!/usr/bin/env bash
# Prerequisite smoke tests only. Never invoke on a persistent/self-hosted machine.
set -euo pipefail
if [[ "${1:-}" != --github-hosted-only || "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${ImageOS:-}" != ubuntu24 || "$(id -u)" == 0 ]]; then
  echo 'Refusing: requires explicit GitHub-hosted Ubuntu 24 VM enrollment.' >&2
  exit 2
fi
[[ -d "${RUNNER_TEMP:?}" && "$(ps -p 1 -o comm= | xargs)" == systemd ]]
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]]
sudo -n true
# Cross-user and rootless namespace commands need a universally traversable cwd.
cd /
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends podman uidmap fuse-overlayfs slirp4netns passt xfsprogs openssh-server busybox-static
# Shared probe paths must be traversable outside the runner's private home.
work="$(mktemp -d /tmp/fishhat-native.XXXXXXXX)"
account="dtci$(id -u)"; account_created=0; mounted=0; ssh_pid=''; manager_dropin=''
cleanup() {
  status=$?
  set +e
  if [[ -n "$ssh_pid" ]]; then sudo kill "$ssh_pid"; fi
  if ((account_created)); then
    uid="$(id -u "$account")"
    sudo runuser -u "$account" -- env -i HOME="/home/$account" PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user stop ci-probe.service
    sudo loginctl terminate-user "$account"
    sudo loginctl disable-linger "$account"
    sudo userdel -r "$account"
  fi
  if [[ -n "$manager_dropin" ]]; then
    sudo rm -f -- "$manager_dropin"
    sudo rmdir -- "$(dirname "$manager_dropin")"
    sudo systemctl daemon-reload
  fi
  if ((mounted)); then sudo umount "$work/xfs"; fi
  # Keep no private keys/logs as CI artifacts. The VM is discarded after this job.
  sudo rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
if id "$account" >/dev/null 2>&1; then echo 'Refusing existing test account' >&2; exit 2; fi
sudo useradd -m -s /bin/bash "$account"; account_created=1
uid="$(id -u "$account")"
grep -q "^$account:" /etc/subuid
grep -q "^$account:" /etc/subgid
# Generators inherit the manager's startup context, not each systemctl caller's.
probe_dropin="/run/systemd/system/user@$uid.service.d/50-fishhat-probe.conf"
[[ ! -e "$probe_dropin" ]]
manager_dropin="$probe_dropin"
sudo install -d "$(dirname "$manager_dropin")"
printf '[Service]\nEnvironment=XDG_CONFIG_HOME=/home/%s/.config\n' "$account" | sudo tee "$manager_dropin" >/dev/null
sudo systemctl daemon-reload
sudo loginctl enable-linger "$account"
sudo systemctl start "user@$uid.service"
user_run() {
  sudo runuser -u "$account" -- env -i HOME="/home/$account" USER="$account" LOGNAME="$account" PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$uid" "$@"
}
[[ "$(user_run podman info --format '{{.Host.Security.Rootless}}')" == true ]]
[[ "$(user_run podman info --format '{{.Host.CgroupsVersion}}')" == v2 ]]
[[ "$(user_run podman info --format '{{.Store.GraphDriverName}}')" == overlay ]]
# Build a tiny local image without any registry or test-container network.
sudo install -d -o "$account" -g "$account" "/home/$account/context"
sudo install -o "$account" -g "$account" /bin/busybox "/home/$account/context/busybox"
printf '%s\n' 'FROM scratch' 'COPY busybox /bin/busybox' 'ENTRYPOINT ["/bin/busybox"]' | sudo tee "/home/$account/context/Containerfile" >/dev/null
user_run podman build --network=none --pull=never --layers=false -t localhost/fishhat-ci:local "/home/$account/context"
[[ "$(user_run podman run --rm --network=none --cap-drop=all --security-opt=no-new-privileges localhost/fishhat-ci:local echo rootless-ok)" == rootless-ok ]]
# Verify real ancestor settings; this is not OOM/pressure qualification.
sudo systemctl set-property --runtime "user-$uid.slice" MemoryHigh=384M MemoryMax=512M TasksMax=256 CPUQuota=100%
[[ "$(cat "/sys/fs/cgroup/user.slice/user-$uid.slice/memory.max")" == 536870912 ]]
[[ "$(cat "/sys/fs/cgroup/user.slice/user-$uid.slice/pids.max")" == 256 ]]
# Exercise the native rootless Quadlet generator, not a hand-written replacement unit.
sudo install -d -o "$account" -g "$account" "/home/$account/.config/containers/systemd"
cat <<'EOF' | sudo tee "/home/$account/.config/containers/systemd/ci-probe.container" >/dev/null
[Container]
Image=localhost/fishhat-ci:local
Pull=never
Network=none
Exec=echo quadlet-ok
[Service]
Type=oneshot
Restart=no
EOF
sudo chown "$account:$account" "/home/$account/.config/containers/systemd/ci-probe.container"
user_run env "QUADLET_UNIT_DIRS=/home/$account/.config/containers/systemd" /usr/libexec/podman/quadlet --user --dryrun
user_run systemctl --user daemon-reload
if ! user_run systemctl --user start ci-probe.service; then
  user_run systemd-analyze --user --generators=true verify ci-probe.service
  exit 1
fi
[[ "$(user_run systemctl --user show ci-probe.service -p FragmentPath --value)" == "/run/user/$uid/systemd/generator/ci-probe.service" ]]
for _ in $(seq 1 40); do
  state="$(user_run systemctl --user show ci-probe.service -p ActiveState --value)"
  [[ "$state" != active && "$state" != activating ]] && break
  sleep 0.25
done
[[ "$state" == inactive ]]
[[ "$(user_run systemctl --user show ci-probe.service -p Result --value)" == success ]]
[[ "$(user_run systemctl --user show ci-probe.service -p ExecMainStatus --value)" == 0 ]]
# XFS is a disposable loop device only; never format a physical block device.
truncate -s 768M "$work/xfs.img"
sudo mkfs.xfs -q -f "$work/xfs.img"
mkdir "$work/xfs"; chmod 0755 "$work"
sudo mount -o loop,prjquota,nosuid,nodev "$work/xfs.img" "$work/xfs"; mounted=1
sudo mkdir "$work/xfs/account"
sudo xfs_quota -x -c "project -s -p $work/xfs/account 1001" "$work/xfs"
sudo xfs_quota -x -c 'limit -p bhard=8m ihard=64 1001' "$work/xfs"
sudo chown "$account:$account" "$work/xfs/account"
user_run /usr/bin/python3 - "$work/xfs/account" <<'PY'
import errno, os, pathlib, sys
p=pathlib.Path(sys.argv[1])
try:
    with (p/'grow').open('wb',buffering=0) as f:
        for _ in range(16): f.write(b'x' * 1048576)
        os.fsync(f.fileno())
except OSError as e:
    if e.errno != errno.EDQUOT: raise
else: raise AssertionError('byte quota not enforced')
(p/'grow').unlink()
created=[]
try:
    for i in range(256):
        f=p/str(i); f.touch(exist_ok=False); created.append(f)
except OSError as e:
    if e.errno != errno.EDQUOT: raise
else: raise AssertionError('inode quota not enforced')
for f in created:f.unlink()
print('xfs-byte-and-inode-quota-ok')
PY
# Independent loopback sshd fixture; do not alter the runner's global sshd config.
ssh-keygen -q -t ed25519 -N '' -f "$work/server"
ssh-keygen -q -t ed25519 -N '' -f "$work/client"
cp "$work/client.pub" "$work/authorized_keys"
cat > "$work/sshd_config" <<EOF
Port 22229
ListenAddress 127.0.0.1
HostKey $work/server
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
StrictModes no
UsePAM no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers $(id -un)
DisableForwarding yes
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
ForceCommand /usr/bin/printf ssh-fixture-ok
LogLevel ERROR
EOF
sudo mkdir -p /run/sshd
sudo /usr/sbin/sshd -t -f "$work/sshd_config"
sudo /usr/sbin/sshd -f "$work/sshd_config" -E "$work/sshd.log"
ssh_pid="$(cat "$work/sshd.pid")"
printf '[127.0.0.1]:22229 %s\n' "$(cut -d' ' -f1,2 "$work/server.pub")" > "$work/known_hosts"
result="$(ssh -F /dev/null -T -p 22229 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/known_hosts" "$(id -un)@127.0.0.1" arbitrary-input)"
[[ "$result" == ssh-fixture-ok ]]
if ssh -F /dev/null -T -p 22229 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/dev/null "$(id -un)@127.0.0.1" info 2>/dev/null; then
  echo 'Unknown SSH host key was accepted' >&2; exit 1
fi
printf '%s\n' '{"scope":"hosted-runner-prerequisites-only","systemd_cgroup2":true,"rootless_overlay":true,"quadlet":true,"xfs_byte_inode_quotas":true,"loopback_ssh":true,"native_tools_qualified":false}'
