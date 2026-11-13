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
observation_helper="$(dirname "$timeout_helper")/native_smoke_observation.py"
# Shared deadlines bound the complete stage, including successive commands.
kill_timeout="$(python3 "$timeout_helper" seconds 5)"
contact_timeout="$(python3 "$timeout_helper" units 30)"
probe_stage=''; stage_started=0; stage_deadline=''; saved_uid=''; saved_gid=''; slice_properties_owned=0
begin_stage() {
  finish_stage 0
  probe_stage="$1"; stage_started=$SECONDS
  stage_deadline="$(python3 "$timeout_helper" deadline "$2")"
  printf 'native-prerequisite stage=%s status=started budget_nominal_seconds=%s\n' "$probe_stage" "$2"
}
finish_stage() {
  if [[ -n "$probe_stage" ]]; then
    local result=passed
    if (( $1 != 0 )); then result=failed; fi
    printf 'native-prerequisite stage=%s status=%s exit=%s elapsed_seconds=%s\n' \
      "$probe_stage" "$result" "$1" "$((SECONDS - stage_started))"
    probe_stage=''
  fi
}
root_run() {
  local remaining_timeout
  remaining_timeout="$(python3 "$timeout_helper" remaining "$stage_deadline")" || return "$?"
  sudo -n timeout -k "$kill_timeout" "$remaining_timeout" "$@"
}
observe_control() {
  local control_name="$1" control_status
  shift
  printf 'native-prerequisite control=%s status=started\n' "$control_name" >&2
  if "$@"; then
    printf 'native-prerequisite control=%s status=passed exit=0\n' "$control_name" >&2
    return 0
  else
    control_status=$?
    printf 'native-prerequisite control=%s status=failed exit=%s\n' "$control_name" "$control_status" >&2
    return "$control_status"
  fi
}


observe_owned_cleanup() {
  (cd "$(dirname "$timeout_helper")/.." && root_run python3 -m scripts.native_smoke_cleanup observe "$account" "$saved_uid" "$saved_gid" "$work" "$stage_deadline")
}
observe_owned_slice_configuration() {
  (cd "$(dirname "$timeout_helper")/.." && root_run python3 -m scripts.native_smoke_cleanup configuration-clear "$account" "$saved_uid" "$saved_gid" "$work" "$stage_deadline")
}
remove_owned_account() {
  root_run userdel -r "$account" 2>"$work/userdel.stderr"
}
bounded_run() {
  local remaining_timeout
  remaining_timeout="$(python3 "$timeout_helper" remaining "$stage_deadline")" || return "$?"
  timeout -k "$kill_timeout" "$remaining_timeout" "$@"
}
# Cross-user and rootless namespace commands need a universally traversable cwd.
cd /
export DEBIAN_FRONTEND=noninteractive
work=''
account="dtci$(id -u)"; account_created=0; mounted=0; ssh_pid=''; manager_environment=''
cleanup() {
  status=$?
  set +e
  finish_stage "$status"
  begin_stage cleanup 120
  cleanup_failed=0
  if [[ -n "$ssh_pid" ]]; then root_run kill "$ssh_pid" || cleanup_failed=1; fi
  if ((account_created)); then
    uid="$(id -u "$account")"
    observe_control cleanup-user-service-stop root_run runuser -u "$account" -- env -i HOME="/home/$account" PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user stop ci-probe.service
    if declare -F user_run >/dev/null; then
      observe_control cleanup-runtime-reset user_run podman system reset --force || cleanup_failed=1
    fi
    # Prevent manager respawn, then wait for its stop and pending session teardown.
    observe_control cleanup-disable-linger root_run loginctl disable-linger "$account" || cleanup_failed=1
    observe_control cleanup-terminate-user root_run loginctl terminate-user "$account" || cleanup_failed=1
    observe_control cleanup-manager-stop root_run systemctl stop "user@$uid.service" || cleanup_failed=1
    account_removed=0
    cleanup_deadline="$(python3 "$timeout_helper" deadline 10)"
    while python3 "$timeout_helper" pending "$cleanup_deadline"; do
      observe_control cleanup-account-remove remove_owned_account
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
  if ((slice_properties_owned)); then
    observe_control cleanup-slice-properties root_run systemctl --quiet revert "user-$saved_uid.slice" || cleanup_failed=1
  fi
  if [[ -n "$manager_environment" ]]; then
    observe_control cleanup-generator-remove root_run rm -f -- "$manager_environment" || cleanup_failed=1
  fi
  if ((mounted)); then observe_control cleanup-filesystem-unmount root_run umount "$work/xfs" || cleanup_failed=1; fi
  # Keep no private keys/logs as CI artifacts. The VM is discarded after this job.
  if [[ -n "$work" ]]; then
    observe_control cleanup-work-remove root_run rm -rf -- "$work" || cleanup_failed=1
  fi
  if ((account_created)); then
    observe_control cleanup-observation observe_owned_cleanup || cleanup_failed=1
  fi
  if ((cleanup_failed)); then
    echo 'Native prerequisite cleanup failed' >&2
    if ((status == 0)); then status=1; fi
  else
    echo 'Disposable probe resources removed.'
  fi
  finish_stage "$cleanup_failed"
  exit "$status"
}
trap cleanup EXIT
begin_stage package-update 300
root_run apt-get -o "Acquire::http::Timeout=$contact_timeout" -o "Acquire::https::Timeout=$contact_timeout" -o Acquire::Retries=0 -o "DPkg::Lock::Timeout=$contact_timeout" update --error-on=any -qq
begin_stage package-install 600
root_run apt-get -o "Acquire::http::Timeout=$contact_timeout" -o "Acquire::https::Timeout=$contact_timeout" -o Acquire::Retries=0 -o "DPkg::Lock::Timeout=$contact_timeout" install -y --no-install-recommends podman uidmap fuse-overlayfs slirp4netns passt xfsprogs openssh-server busybox-static
begin_stage account 120
# Shared probe paths must be traversable outside the runner's private home.
work="$(mktemp -d /tmp/fishhat-native.XXXXXXXX)"
if id "$account" >/dev/null 2>&1; then echo 'Refusing existing test account' >&2; exit 2; fi
observe_control account-create root_run useradd -m -s /bin/bash "$account"; account_created=1
uid="$(id -u "$account")"
saved_uid="$uid"
saved_gid="$(id -g "$account")"
[[ "$(id -gn "$account")" == "$account" ]]
grep -q "^$account:" /etc/subuid
grep -q "^$account:" /etc/subgid
# Run after the image's environment import, and affect only the probe account.
probe_environment="/usr/lib/systemd/user-environment-generators/99-fishhat-probe-$uid"
[[ ! -e "$probe_environment" && ! -L "$probe_environment" ]]
manager_environment="$probe_environment"
observe_control generator-directory-check root_run test -d "$(dirname "$manager_environment")"
cat <<EOF | observe_control generator-write root_run tee "$manager_environment" >/dev/null
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
observe_control generator-mode root_run chmod 0755 "$manager_environment"
root_run install -d -m 0700 -o "$account" -g "$account" "/home/$account/tmp"
observe_control generator-metadata root_run python3 "$observation_helper" "$manager_environment"
generator_status=0
probe_context_text="$(observe_control generator-execute root_run runuser -u "$account" -- "$manager_environment")" || generator_status=$?
if ((generator_status == 0)) && [[ -z "$probe_context_text" ]]; then generator_status=1; fi
access_status=0
observe_control generator-access root_run runuser -u "$account" -- /bin/sh -c '
probe_index=0
for probe_path do
  case "$probe_index" in
    0) probe_role=prefix ;;
    1) probe_role=library ;;
    2) probe_role=manager-library ;;
    3) probe_role=generator-directory ;;
    4) probe_role=generator ;;
    5) probe_role=interpreter ;;
  esac
  if [ -r "$probe_path" ]; then probe_read=allowed; else probe_read=denied; fi
  if [ -x "$probe_path" ]; then probe_execute=allowed; else probe_execute=denied; fi
  printf "native-prerequisite generator-access role=%s read=%s execute=%s\n" "$probe_role" "$probe_read" "$probe_execute" >&2
  probe_index=$((probe_index + 1))
done
' sh /usr /usr/lib /usr/lib/systemd "$(dirname "$manager_environment")" "$manager_environment" /bin/sh || access_status=$?

if ((generator_status != 0)); then exit "$generator_status"; fi
if ((access_status != 0)); then exit "$access_status"; fi
[[ -n "$probe_context_text" ]]
mapfile -t probe_context <<< "$probe_context_text"
observe_control linger-enable root_run loginctl enable-linger "$account"
observe_control manager-start root_run systemctl start "user@$uid.service"
user_run() {
  root_run runuser -u "$account" -- env -i "${probe_context[@]}" "$@"
}
verify_manager_context() {
  local binding manager_values expected_values
  local -a context_keys=() context_values=()
  for binding in "${probe_context[@]}"; do
    context_keys+=("${binding%%=*}")
    context_values+=("${binding#*=}")
  done
  manager_values="$(user_run systemd-run --user --quiet --wait --pipe --collect /usr/bin/printenv "${context_keys[@]}")" || return "$?"
  expected_values="$(printf '%s\n' "${context_values[@]}")"
  [[ "$manager_values" == "$expected_values" ]]
}
observe_control manager-environment-check verify_manager_context
begin_stage rootless-runtime 180
[[ "$(user_run podman info --format '{{.Host.Security.Rootless}}')" == true ]]
[[ "$(user_run podman info --format '{{.Host.CgroupsVersion}}')" == v2 ]]
[[ "$(user_run podman info --format '{{.Store.GraphDriverName}}')" == overlay ]]
# Build a tiny local image without any registry or test-container network.
root_run install -d -o "$account" -g "$account" "/home/$account/context"
root_run install -o "$account" -g "$account" /bin/busybox "/home/$account/context/busybox"
printf '%s\n' 'FROM scratch' 'COPY busybox /bin/busybox' 'ENTRYPOINT ["/bin/busybox"]' | root_run tee "/home/$account/context/Containerfile" >/dev/null
user_run podman build --network=none --pull=never --layers=false -t localhost/fishhat-ci:local "/home/$account/context"
[[ "$(user_run podman run --rm --network=none --cap-drop=all --security-opt=no-new-privileges localhost/fishhat-ci:local echo rootless-ok)" == rootless-ok ]]
begin_stage cgroup-controls 120
# Verify real ancestor settings; this is not OOM/pressure qualification.
observe_control slice-configuration-custody observe_owned_slice_configuration
slice_properties_owned=1
root_run systemctl set-property --runtime "user-$uid.slice" MemoryHigh=384M MemoryMax=512M TasksMax=256 CPUQuota=100%
[[ "$(cat "/sys/fs/cgroup/user.slice/user-$uid.slice/memory.max")" == 536870912 ]]
[[ "$(cat "/sys/fs/cgroup/user.slice/user-$uid.slice/pids.max")" == 256 ]]
begin_stage quadlet 180
# Require direct commands and native user services to resolve the same owned image.
image_id="$(user_run podman image inspect localhost/fishhat-ci:local --format '{{.Id}}')"
unit_image_id="$(user_run systemd-run --user --quiet --wait --pipe --collect --property=Delegate=yes /usr/bin/podman image inspect localhost/fishhat-ci:local --format '{{.Id}}')"
[[ "$unit_image_id" == "$image_id" ]]
# Exercise the native rootless Quadlet generator, not a hand-written replacement unit.
root_run install -d -o "$account" -g "$account" "/home/$account/.config" "/home/$account/.config/containers" "/home/$account/.config/containers/systemd"
cat <<'EOF' | root_run tee "/home/$account/.config/containers/systemd/ci-probe.container" >/dev/null
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
root_run chown "$account:$account" "/home/$account/.config/containers/systemd/ci-probe.container"
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
begin_stage xfs-setup 120
# XFS is a disposable loop device only; never format a physical block device.
truncate -s 768M "$work/xfs.img"
root_run mkfs.xfs -q -f "$work/xfs.img"
mkdir "$work/xfs"; chmod 0755 "$work"
root_run mount -o loop,prjquota,nosuid,nodev "$work/xfs.img" "$work/xfs"; mounted=1
root_run mkdir "$work/xfs/account" "$work/xfs/control"
root_run xfs_quota -x -c "project -s -p $work/xfs/account 1001" "$work/xfs"
root_run chown "$account:$account" "$work/xfs/account" "$work/xfs/control"
begin_stage xfs-bytes 120
# Isolate each quota dimension; outside-project controls must still succeed.
root_run xfs_quota -x -c 'limit -p bhard=8m ihard=0 1001' "$work/xfs"
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
begin_stage xfs-inodes 120
root_run xfs_quota -x -c 'limit -p bhard=0 ihard=64 1001' "$work/xfs"
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
begin_stage loopback-ssh 120
# Independent loopback sshd fixture; do not alter the runner's global sshd config.
bounded_run ssh-keygen -q -t ed25519 -N '' -f "$work/server"
bounded_run ssh-keygen -q -t ed25519 -N '' -f "$work/client"
root_run install -d -m 0700 -o "$account" -g "$account" "/home/$account/.ssh"
root_run install -m 0600 -o "$account" -g "$account" "$work/client.pub" "/home/$account/.ssh/authorized_keys"
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
root_run mkdir -p /run/sshd
root_run /usr/sbin/sshd -t -f "$work/sshd_config"
root_run /usr/sbin/sshd -f "$work/sshd_config" -E "$work/sshd.log"
ssh_pid="$(cat "$work/sshd.pid")"
printf '[127.0.0.1]:22229 %s\n' "$(cut -d' ' -f1,2 "$work/server.pub")" > "$work/known_hosts"
if ! result="$(bounded_run ssh -F /dev/null -T -p 22229 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes -o "ConnectTimeout=$contact_timeout" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/known_hosts" "${account}@127.0.0.1" arbitrary-input)"; then
  root_run /usr/bin/tail -n 40 "$work/sshd.log"
  exit 1
fi
[[ "$result" == ssh-fixture-ok ]]
if bounded_run ssh -F /dev/null -T -p 22229 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes -o "ConnectTimeout=$contact_timeout" -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/dev/null "${account}@127.0.0.1" info 2>"$work/untrusted-host.stderr"; then
  echo 'Unknown SSH host key was accepted' >&2; exit 1
else
  host_key_status=$?
  if ((host_key_status != 255)) || ! grep -Fq 'Host key verification failed.' "$work/untrusted-host.stderr"; then
    echo 'Unknown-host-key check did not establish the expected rejection' >&2
    exit 1
  fi
fi
finish_stage 0
printf '%s\n' '{"scope":"hosted-runner-prerequisites-only","systemd_cgroup2":true,"rootless_overlay":true,"quadlet":true,"xfs_byte_inode_quotas":true,"loopback_ssh":true,"native_tools_qualified":false}'
