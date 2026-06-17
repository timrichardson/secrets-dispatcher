#!/usr/bin/env bash
set -euo pipefail

SCENARIO=${SCENARIO:-secure-local}
DESKTOP_USER=${DESKTOP_USER:-sdtest}
GNOME_PROFILE=${GNOME_PROFILE:-desktop}
BINARY=${BINARY:-/usr/local/bin/secrets-dispatcher}

export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

log() {
	printf '[vm-smoke] %s\n' "$*"
}

fail_with_unit_logs() {
	local unit=$1
	log "system unit status for $unit"
	systemctl status "$unit" --no-pager || true
	log "system unit journal for $unit"
	journalctl -u "$unit" --no-pager -n 200 || true
	exit 1
}

install_packages() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends \
		ca-certificates curl sudo dbus dbus-user-session dbus-x11 \
		gnome-keyring libsecret-tools systemd-container procps
	if [ "$GNOME_PROFILE" = desktop ]; then
		apt-get install -y --no-install-recommends ubuntu-desktop-minimal || \
			apt-get install -y --no-install-recommends gnome-session gdm3
	fi
}

ensure_desktop_user() {
	if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
		useradd -m -s /bin/bash "$DESKTOP_USER"
	fi
	usermod -aG sudo "$DESKTOP_USER" >/dev/null 2>&1 || true
}

desktop_uid() {
	id -u "$DESKTOP_USER"
}

run_as_desktop() {
	local uid home
	uid=$(desktop_uid)
	home=/home/$DESKTOP_USER
	(
		cd "$home"
		runuser -u "$DESKTOP_USER" -- env -i \
			HOME="$home" \
			USER="$DESKTOP_USER" \
			LOGNAME="$DESKTOP_USER" \
			SHELL=/bin/bash \
			PATH="$PATH" \
			XDG_RUNTIME_DIR="/run/user/$uid" \
			DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
			"$@"
	)
}

start_user_session_bus() {
	local uid runtime bus
	uid=$(desktop_uid)
	runtime=/run/user/$uid
	bus=$runtime/bus
	loginctl enable-linger "$DESKTOP_USER" || true
	systemctl start "user@$uid.service"
	for _ in $(seq 1 60); do
		if [ -S "$bus" ]; then
			return 0
		fi
		sleep 1
	done
	log "user manager status follows"
	systemctl status "user@$uid.service" --no-pager || true
	exit 1
}

wait_for_user_unit() {
	local unit=$1
	for _ in $(seq 1 60); do
		if run_as_desktop systemctl --user is-active --quiet "$unit"; then
			return 0
		fi
		sleep 1
	done
	log "user unit status for $unit"
	run_as_desktop systemctl --user status "$unit" --no-pager || true
	log "user unit journal for $unit"
	run_as_desktop journalctl --user -u "$unit" --no-pager -n 200 || true
	exit 1
}

secret_service_has_owner() {
	run_as_desktop busctl --user --timeout=5 call \
		org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner \
		s org.freedesktop.secrets 2>/dev/null | grep -q 'b true'
}

wait_for_secret_service_owner() {
	for _ in $(seq 1 60); do
		if secret_service_has_owner; then
			return 0
		fi
		sleep 1
	done
	log "org.freedesktop.secrets owner did not appear"
	run_as_desktop busctl --user --no-pager list || true
	run_as_desktop systemctl --user status secrets-dispatcher.service --no-pager || true
	run_as_desktop journalctl --user -u secrets-dispatcher.service --no-pager -n 200 || true
	return 1
}

assert_tcp_api_requires_auth() {
	local code
	code=$(run_as_desktop curl -sS -o /tmp/secrets-dispatcher-status.json -w '%{http_code}' http://127.0.0.1:8484/api/v1/status || true)
	if [ "$code" != 401 ]; then
		log "unexpected TCP status API response code: $code"
		cat /tmp/secrets-dispatcher-status.json 2>/dev/null || true
		return 1
	fi
}

wait_for_unix_socket() {
	local path=$1
	for _ in $(seq 1 60); do
		if [ -S "$path" ]; then
			return 0
		fi
		sleep 1
	done
	log "timed out waiting for Unix socket $path"
	return 1
}

assert_secure_api_requires_auth() {
	local socket=/run/secrets-dispatcher/$DESKTOP_USER/api.sock
	local code
	wait_for_unix_socket "$socket"
	code=$(curl -sS --unix-socket "$socket" -o /tmp/secrets-dispatcher-secure-status.json -w '%{http_code}' http://localhost/api/v1/status || true)
	if [ "$code" != 401 ]; then
		log "unexpected secure API response code: $code"
		cat /tmp/secrets-dispatcher-secure-status.json 2>/dev/null || true
		return 1
	fi
}

install_normal_local_mode() {
	log "installing normal local mode"
	run_as_desktop "$BINARY" service install --mode local --backend gnome-keyring --start
	wait_for_user_unit secrets-dispatcher.service
	wait_for_secret_service_owner
	assert_tcp_api_requires_auth
	log "normal local mode installed successfully"
}

uninstall_normal_mode() {
	log "uninstalling normal user-mode service"
	run_as_desktop "$BINARY" service uninstall || true
	for _ in $(seq 1 30); do
		if ! run_as_desktop systemctl --user is-active --quiet secrets-dispatcher.service; then
			return 0
		fi
		sleep 1
	done
	run_as_desktop systemctl --user status secrets-dispatcher.service --no-pager || true
	return 1
}

write_secure_trusted_config() {
	local uid config_dir config_file sockets_dir
	uid=$(desktop_uid)
	config_dir=/etc/secrets-dispatcher/secure
	config_file=$config_dir/$DESKTOP_USER.yaml
	sockets_dir=/run/user/$uid/secrets-dispatcher/sockets
	mkdir -p "$config_dir"
	cat >"$config_file" <<EOF_CONFIG
listen: "127.0.0.1:8484"
serve:
  log_level: debug
  timeout: 30s
  notifications: false
  upstream:
    type: session_bus
  downstream:
    - type: sockets
      path: "$sockets_dir"
  secure_backend:
    provider: gnome-keyring
EOF_CONFIG
	chown root:root "$config_file"
	chmod 0644 "$config_file"
}

assert_secure_provisioning_artifacts() {
	local backend_user=secrets-$DESKTOP_USER
	local backend_home=/var/lib/secret-companion/$DESKTOP_USER
	id "$backend_user" >/dev/null
	[ -d "$backend_home" ]
	[ "$(stat -c '%a' "$backend_home")" = 700 ]
	[ "$(stat -c '%U' "$backend_home")" = "$backend_user" ]
	[ -f /etc/systemd/system/secrets-dispatcher-secure@.service ]
	grep -q 'secure-launch --user %i --backend gnome-keyring' /etc/systemd/system/secrets-dispatcher-secure@.service
}

install_secure_local_mode() {
	local unit=secrets-dispatcher-secure@$DESKTOP_USER.service
	log "provisioning secure-local mode"
	"$BINARY" provision --mode secure-local --user "$DESKTOP_USER" --binary "$BINARY"
	write_secure_trusted_config
	"$BINARY" provision --mode secure-local --user "$DESKTOP_USER" --binary "$BINARY" --check
	assert_secure_provisioning_artifacts

	log "installing secure-local user config and activation masks"
	run_as_desktop "$BINARY" service install --mode secure-local

	log "starting root-managed secure-local unit $unit"
	systemctl enable --now "$unit"
	for _ in $(seq 1 60); do
		if systemctl is-active --quiet "$unit"; then
			break
		fi
		sleep 1
	done
	systemctl is-active --quiet "$unit" || fail_with_unit_logs "$unit"
	wait_for_secret_service_owner || fail_with_unit_logs "$unit"
	assert_secure_api_requires_auth
	log "secure-local mode installed successfully"
}

cleanup_secure_local() {
	local unit=secrets-dispatcher-secure@$DESKTOP_USER.service
	systemctl disable --now "$unit" >/dev/null 2>&1 || true
}

log "guest distro: $(. /etc/os-release && printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-unknown}")"
log "scenario=$SCENARIO gnome_profile=$GNOME_PROFILE desktop_user=$DESKTOP_USER"

install_packages
ensure_desktop_user
start_user_session_bus
"$BINARY" version >/dev/null

case "$SCENARIO" in
normal)
	install_normal_local_mode
	;;
secure-local)
	install_normal_local_mode
	uninstall_normal_mode
	install_secure_local_mode
	cleanup_secure_local
	;;
*)
	echo "unsupported SCENARIO=$SCENARIO (want normal or secure-local)" >&2
	exit 2
	;;
esac

log "smoke test complete"
