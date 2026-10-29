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
timeout_helper="$(cd "$(dirname "$0")/.." && pwd)/validation_timeouts.py"
# Cross-user and rootless namespace commands need a universally traversable cwd.
cd /
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends podman uidmap fuse-overlayfs slirp4netns passt xfsprogs openssh-server busybox-static
# Shared probe paths must be traversable outside the runner's private home.
work="$(mktemp -d /tmp/fishhat-native.XXXXXXXX)"
account="dtci$(id -u)"; account_created=0; mounted=0; ssh_pid=''; manager_environment=''
cleanup() {
  status=$?
  set +e
  cleanup_failed=0
  if [[ -n "$ssh_pid" ]]; then sudo kill "$ssh_pid" || cleanup_failed=1; fi
  if ((account_created)); then
    uid="$(id -u "$account")"
    sudo runuser -u "$account" -- env -i HOME="/home/$account" PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user stop ci-probe.service
    if declare -F user_run >/dev/null; then
      user_run podman system reset --force || cleanup_failed=1
    fi
    # Prevent manager respawn, then wait for its stop and pending session teardown.
    sudo loginctl disable-linger "$account" || cleanup_failed=1
    sudo loginctl terminate-user "$account" || cleanup_failed=1
    sudo systemctl stop "user@$uid.service" || cleanup_failed=1
    account_removed=0
    cleanup_deadline="$(python3 "$timeout_helper" deadline 10)"
    while python3 "$timeout_helper" pending "$cleanup_deadline"; do
      sudo userdel -r "$account" 2>"$work/userdel.stderr"
      account_remove_status=$?
      if ((account_remove_status == 0)); then
        account_removed=1
        break
      fi
      # Ubuntu userdel reports a still-busy account with exit status 8.
      if ((account_remove_status != 8)); then break; fi
      sleep 0.25
    done
    if ((!account_removed)); then
      cat "$work/userdel.stderr" >&2
      cleanup_failed=1
    fi
  fi
  if [[ -n "$manager_environment" ]]; then
    sudo rm -f -- "$manager_environment" || cleanup_failed=1
  fi
  if ((mounted)); then sudo umount "$work/xfs" || cleanup_failed=1; fi
  # Keep no private keys/logs as CI artifacts. The VM is discarded after this job.
  sudo rm -rf -- "$work" || cleanup_failed=1
  if ((cleanup_failed)); then
    echo 'Native prerequisite cleanup failed' >&2
    if ((status == 0)); then status=1; fi
  else
    echo 'Disposable probe resources removed.'
  fi
  exit "$status"
}
trap cleanup EXIT
if id "$account" >/dev/null 2>&1; then echo 'Refusing existing test account' >&2; exit 2; fi
sudo useradd -m -s /bin/bash "$account"; account_created=1
uid="$(id -u "$account")"
grep -q "^$account:" /etc/subuid
grep -q "^$account:" /etc/subgid
# Run after the image's environment import, and affect only the probe account.
probe_environment="/run/systemd/user-environment-generators/99-fishhat-probe-$uid"
[[ ! -e "$probe_environment" && ! -L "$probe_environment" ]]
manager_environment="$probe_environment"
sudo install -d -m 0755 "$(dirname "$manager_environment")"
cat <<EOF | sudo tee "$manager_environment" >/dev/null
#!/bin/sh
[ "\$(/usr/bin/id -u)" = "$uid" ] || exit 0
/usr/bin/cat <<'PROBE_ENV'
HOME=/home/$account
USER=$account
LOGNAME=$account
PATH=/usr/bin:/bin
XDG_CONFIG_HOME=/home/$account/.config
XDG_DATA_HOME=/home/$account/.local/share
XDG_CACHE_HOME=/home/$account/.cache
XDG_STATE_HOME=/home/$account/.local/state
XDG_RUNTIME_DIR=/run/user/$uid
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus
TMPDIR=/home/$account/tmp
PROBE_ENV
EOF
sudo chmod 0755 "$manager_environment"
sudo install -d -m 0700 -o "$account" -g "$account" "/home/$account/tmp"
probe_context_text="$(sudo runuser -u "$account" -- "$manager_environment")"
[[ -n "$probe_context_text" ]]
mapfile -t probe_context <<< "$probe_context_text"
sudo loginctl enable-linger "$account"
sudo systemctl start "user@$uid.service"
user_run() {
  sudo runuser -u "$account" -- env -i "${probe_context[@]}" "$@"
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
# Require direct commands and native user services to resolve the same owned image.
image_id="$(user_run podman image inspect localhost/fishhat-ci:local --format '{{.Id}}')"
unit_image_id="$(user_run systemd-run --user --quiet --wait --pipe --collect --property=Delegate=yes /usr/bin/podman image inspect localhost/fishhat-ci:local --format '{{.Id}}')"
[[ "$unit_image_id" == "$image_id" ]]
# Exercise the native rootless Quadlet generator, not a hand-written replacement unit.
sudo install -d -o "$account" -g "$account" "/home/$account/.config" "/home/$account/.config/containers" "/home/$account/.config/containers/systemd"
cat <<'EOF' | sudo tee "/home/$account/.config/containers/systemd/ci-probe.container" >/dev/null
[Container]
Image=localhost/fishhat-ci:local
Pull=never
Network=none
Exec=echo quadlet-ok
[Service]
Type=oneshot
Restart=no
StandardOutput=append:%t/ci-probe.stdout
StandardError=append:%t/ci-probe.stderr
EOF
sudo chown "$account:$account" "/home/$account/.config/containers/systemd/ci-probe.container"
user_run env "QUADLET_UNIT_DIRS=/home/$account/.config/containers/systemd" /usr/libexec/podman/quadlet --user --dryrun
user_run systemctl --user daemon-reload
if ! user_run systemctl --user start ci-probe.service; then
  user_run systemctl --user show ci-probe.service -p Result -p ExecMainStatus
  user_run /usr/bin/tail -n 40 "/run/user/$uid/ci-probe.stderr" || true
  user_run systemd-analyze --user --generators=true verify ci-probe.service
  exit 1
fi
[[ "$(user_run systemctl --user show ci-probe.service -p FragmentPath --value)" == "/run/user/$uid/systemd/generator/ci-probe.service" ]]
settlement_deadline="$(python3 "$timeout_helper" deadline 10)"
while python3 "$timeout_helper" pending "$settlement_deadline"; do
  state="$(user_run systemctl --user show ci-probe.service -p ActiveState --value)"
  [[ "$state" != active && "$state" != activating ]] && break
  sleep 0.25
done
[[ "$state" == inactive ]]
[[ "$(user_run systemctl --user show ci-probe.service -p Result --value)" == success ]]
[[ "$(user_run systemctl --user show ci-probe.service -p ExecMainStatus --value)" == 0 ]]
[[ "$(user_run /usr/bin/cat "/run/user/$uid/ci-probe.stdout")" == quadlet-ok ]]
# XFS is a disposable loop device only; never format a physical block device.
truncate -s 768M "$work/xfs.img"
sudo mkfs.xfs -q -f "$work/xfs.img"
mkdir "$work/xfs"; chmod 0755 "$work"
sudo mount -o loop,prjquota,nosuid,nodev "$work/xfs.img" "$work/xfs"; mounted=1
sudo mkdir "$work/xfs/account" "$work/xfs/control"
sudo xfs_quota -x -c "project -s -p $work/xfs/account 1001" "$work/xfs"
sudo chown "$account:$account" "$work/xfs/account" "$work/xfs/control"
# Isolate each quota dimension; outside-project controls must still succeed.
sudo xfs_quota -x -c 'limit -p bhard=8m ihard=0 1001' "$work/xfs"
user_run /usr/bin/python3 - "$work/xfs/account" "$work/xfs/control" <<'PY'
import errno, os, pathlib, sys
p, control = map(pathlib.Path, sys.argv[1:])
def grow(path):
    target = 16 * 1048576
    with path.open('wb', buffering=0) as stream:
        while stream.tell() < target:
            written = stream.write(b'x' * min(1048576, target - stream.tell()))
            assert written and written > 0, 'write made no progress'
        os.fsync(stream.fileno())
    assert path.stat().st_size == target

grow(control / 'before')
try:
    grow(p / 'grow')
except OSError as exc:
    if exc.errno != errno.ENOSPC:
        raise
else:
    raise AssertionError('byte quota not enforced')
size = (p / 'grow').stat().st_size
assert 0 < size <= 8 * 1048576
# A full backing filesystem must fail this independent post-limit control.
grow(control / 'after')
for path in (p / 'grow', control / 'before', control / 'after'):
    path.unlink()
print('xfs-byte-quota-ok', size)
PY
sudo xfs_quota -x -c 'limit -p bhard=0 ihard=64 1001' "$work/xfs"
user_run /usr/bin/python3 - "$work/xfs/account" "$work/xfs/control" <<'PY'
import errno, pathlib, sys
p, control = map(pathlib.Path, sys.argv[1:])
def controls(prefix):
    paths = [control / f'{prefix}-{i}' for i in range(256)]
    for path in paths:
        path.touch(exist_ok=False)
    return paths

before = controls('before')
created = []
try:
    for i in range(256):
        path = p / str(i)
        path.touch(exist_ok=False)
        created.append(path)
except OSError as exc:
    if exc.errno != errno.ENOSPC:
        raise
else:
    raise AssertionError('inode quota not enforced')
# The project directory also consumes one of its 64 admitted inodes.
assert 0 < len(created) < 64
# Global inode or block exhaustion must fail this independent control.
after = controls('after')
for path in before + created + after:
    path.unlink()
print('xfs-inode-quota-ok', len(created))
PY
# Independent loopback sshd fixture; do not alter the runner's global sshd config.
ssh-keygen -q -t ed25519 -N '' -f "$work/server"
ssh-keygen -q -t ed25519 -N '' -f "$work/client"
sudo install -d -m 0700 -o "$account" -g "$account" "/home/$account/.ssh"
sudo install -m 0600 -o "$account" -g "$account" "$work/client.pub" "/home/$account/.ssh/authorized_keys"
cat > "$work/sshd_config" <<EOF
Port 22229
ListenAddress 127.0.0.1
HostKey $work/server
PidFile $work/sshd.pid
AuthorizedKeysFile /home/$account/.ssh/authorized_keys
StrictModes yes
UsePAM yes
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers $account
DisableForwarding yes
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
ForceCommand /usr/bin/printf ssh-fixture-ok
LogLevel VERBOSE
EOF
sudo mkdir -p /run/sshd
sudo /usr/sbin/sshd -t -f "$work/sshd_config"
sudo /usr/sbin/sshd -f "$work/sshd_config" -E "$work/sshd.log"
ssh_pid="$(cat "$work/sshd.pid")"
printf '[127.0.0.1]:22229 %s\n' "$(cut -d' ' -f1,2 "$work/server.pub")" > "$work/known_hosts"
if ! result="$(ssh -F /dev/null -T -p 22229 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/known_hosts" "${account}@127.0.0.1" arbitrary-input)"; then
  sudo /usr/bin/tail -n 40 "$work/sshd.log"
  exit 1
fi
[[ "$result" == ssh-fixture-ok ]]
if ssh -F /dev/null -T -p 22229 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/dev/null "${account}@127.0.0.1" info 2>/dev/null; then
  echo 'Unknown SSH host key was accepted' >&2; exit 1
fi
printf '%s\n' '{"scope":"hosted-runner-prerequisites-only","systemd_cgroup2":true,"rootless_overlay":true,"quadlet":true,"xfs_byte_inode_quotas":true,"loopback_ssh":true,"native_tools_qualified":false}'
