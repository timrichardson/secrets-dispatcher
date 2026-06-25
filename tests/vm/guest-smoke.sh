#!/usr/bin/env bash
set -euo pipefail

DISTRO=${DISTRO:-unknown}
MODE=${MODE:-local}
BACKEND=${BACKEND:-gnome-keyring}
SCENARIO=${SCENARIO:-$MODE}
GNOME_PROFILE=${GNOME_PROFILE:-desktop}
DESKTOP_USER=${DESKTOP_USER:-sdtest}
BINARY=${BINARY:-/usr/local/bin/secrets-dispatcher}
GOPASS_SOURCE=${GOPASS_SOURCE:-github.com/gopasspw/gopass@latest}
GOPASS_SECRET_SERVICE_SOURCE=${GOPASS_SECRET_SERVICE_SOURCE:-github.com/nikicat/gopass-secret-service/cmd/gopass-secret@latest}
GOPASS_SECRET_SERVICE_BIN=${GOPASS_SECRET_SERVICE_BIN:-/usr/local/bin/gopass-secret-service}

export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

case "$SCENARIO" in
normal) SCENARIO=local ;;
secure-local) SCENARIO=secure-local-user ;;
esac

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

install_packages_ubuntu() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends \
		ca-certificates curl sudo dbus dbus-user-session dbus-x11 \
		gnome-keyring libsecret-tools systemd-container procps
	if [ "$BACKEND" = gopass ]; then
		apt-get install -y --no-install-recommends gnupg git golang-go
		apt-get install -y --no-install-recommends gopass || true
	fi
	if [ "$SCENARIO" = secure-local-user ]; then
		apt-get install -y --no-install-recommends policykit-1 || \
			apt-get install -y --no-install-recommends polkitd || true
	fi
	if [ "$GNOME_PROFILE" = desktop ]; then
		apt-get install -y --no-install-recommends ubuntu-desktop-minimal || \
			apt-get install -y --no-install-recommends gnome-session gdm3
	fi
}

install_packages_fedora() {
	dnf install -y \
		ca-certificates curl sudo dbus-daemon dbus-tools \
		gnome-keyring libsecret systemd-container procps-ng shadow-utils
	if [ "$BACKEND" = gopass ]; then
		dnf install -y gnupg2 git golang
		dnf install -y gopass || true
	fi
	if [ "$SCENARIO" = secure-local-user ]; then
		dnf install -y polkit || true
	fi
	if [ "$GNOME_PROFILE" = desktop ]; then
		if ! dnf group install -y "GNOME Desktop Environment"; then
			log "GNOME Desktop Environment group install failed, trying core GNOME packages"
			dnf install -y gnome-shell gnome-session gdm || true
		fi
	fi
}

install_packages() {
	case "$DISTRO" in
	ubuntu) install_packages_ubuntu ;;
	fedora) install_packages_fedora ;;
	*)
		. /etc/os-release
		case "${ID:-}" in
		ubuntu|debian) install_packages_ubuntu ;;
		fedora) install_packages_fedora ;;
		*) echo "unsupported guest distro: ${ID:-unknown}" >&2; exit 2 ;;
		esac
		;;
	esac
}

ensure_desktop_user() {
	if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
		useradd -m -s /bin/bash "$DESKTOP_USER"
	fi
	if command -v usermod >/dev/null 2>&1; then
		usermod -aG sudo "$DESKTOP_USER" >/dev/null 2>&1 || true
		usermod -aG wheel "$DESKTOP_USER" >/dev/null 2>&1 || true
	fi
}

desktop_uid() {
	id -u "$DESKTOP_USER"
}

run_as_desktop() {
	local uid home
	uid=$(desktop_uid)
	home="/home/$DESKTOP_USER"
	(
		cd "$home"
		runuser -u "$DESKTOP_USER" -- env -i \
			HOME="$home" \
			USER="$DESKTOP_USER" \
			LOGNAME="$DESKTOP_USER" \
			SHELL=/bin/bash \
			PATH="$PATH" \
			GOPASS_NO_NOTIFY=true \
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

secret_service_owner_pid() {
	local out
	out=$(run_as_desktop busctl --user --timeout=5 call \
		org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixProcessID \
		s org.freedesktop.secrets)
	printf '%s\n' "$out" | awk '{ print $2 }'
}

secret_service_owner_name() {
	local out
	out=$(run_as_desktop busctl --user --timeout=5 call \
		org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner \
		s org.freedesktop.secrets)
	printf '%s\n' "$out" | awk '{ gsub(/"/, "", $2); print $2 }'
}

secret_service_owner_user() {
	local owner out
	owner=$(secret_service_owner_name)
	out=$(run_as_desktop busctl --user --timeout=5 call \
		org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixUser \
		s "$owner")
	printf '%s\n' "$out" | awk '{ print $2 }'
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

assert_secret_service_owned_by_dispatcher() {
	local pid owner_exe expected_exe
	pid=$(secret_service_owner_pid)
	if ! [ "$pid" -gt 0 ] 2>/dev/null; then
		log "could not determine org.freedesktop.secrets owner PID: $pid"
		return 1
	fi
	owner_exe=$(readlink -f "/proc/$pid/exe")
	expected_exe=$(readlink -f "$BINARY")
	if [ "$owner_exe" != "$expected_exe" ]; then
		log "unexpected org.freedesktop.secrets owner: pid=$pid exe=$owner_exe expected=$expected_exe"
		return 1
	fi
}

assert_secret_service_owned_by_desktop_user() {
	local owner_uid uid
	owner_uid=$(secret_service_owner_user)
	uid=$(desktop_uid)
	if [ "$owner_uid" != "$uid" ]; then
		log "unexpected org.freedesktop.secrets owner UID: $owner_uid expected=$uid"
		return 1
	fi
}

assert_secret_service_responds() {
	run_as_desktop busctl --user --timeout=5 call \
		org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Properties GetAll \
		s org.freedesktop.Secret.Service >/dev/null
}

install_go_tool_if_missing() {
	local command_name=$1
	local source=$2
	if command -v "$command_name" >/dev/null 2>&1; then
		return 0
	fi
	log "installing $source with go install"
	GOBIN=/usr/local/bin go install "$source"
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "$command_name not found after installing $source" >&2
		exit 1
	fi
}

install_gopass_secret_service() {
	if [ -x "$GOPASS_SECRET_SERVICE_BIN" ]; then
		return 0
	fi
	if command -v gopass-secret-service >/dev/null 2>&1; then
		GOPASS_SECRET_SERVICE_BIN=$(command -v gopass-secret-service)
		return 0
	fi
	install_go_tool_if_missing gopass-secret "$GOPASS_SECRET_SERVICE_SOURCE"

	local service_command
	service_command=$(command -v gopass-secret)
	mkdir -p "$(dirname -- "$GOPASS_SECRET_SERVICE_BIN")"
	cat >"$GOPASS_SECRET_SERVICE_BIN" <<EOF_WRAPPER
#!/usr/bin/env bash
exec "$service_command" service "\$@"
EOF_WRAPPER
	chmod 0755 "$GOPASS_SECRET_SERVICE_BIN"
}

prepare_gopass_backend() {
	log "preparing disposable gopass backend"
	install_go_tool_if_missing gopass "$GOPASS_SOURCE"
	install_gopass_secret_service
	if [ ! -x "$GOPASS_SECRET_SERVICE_BIN" ]; then
		if command -v gopass-secret-service >/dev/null 2>&1; then
			GOPASS_SECRET_SERVICE_BIN=$(command -v gopass-secret-service)
		else
			echo "gopass-secret-service not found after install" >&2
			exit 1
		fi
	fi

	run_as_desktop mkdir -p "/home/$DESKTOP_USER/.gnupg" "/home/$DESKTOP_USER/.config/gopass"
	run_as_desktop chmod 0700 "/home/$DESKTOP_USER/.gnupg" "/home/$DESKTOP_USER/.config/gopass"

	local email key_file fingerprint
	email="$DESKTOP_USER@secrets-dispatcher.invalid"
	key_file=/tmp/secrets-dispatcher-gopass-key.batch
	cat >"$key_file" <<EOF_KEY
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Secrets Dispatcher VM
Name-Email: $email
Expire-Date: 0
%commit
EOF_KEY
	chown "$DESKTOP_USER:$DESKTOP_USER" "$key_file"
	chmod 0600 "$key_file"
	if ! run_as_desktop gpg --batch --list-secret-keys "$email" >/dev/null 2>&1; then
		run_as_desktop gpg --batch --generate-key "$key_file"
	fi
	fingerprint=$(run_as_desktop gpg --batch --with-colons --list-secret-keys "$email" | awk -F: '/^fpr:/ { print $10; exit }')
	if [ -z "$fingerprint" ]; then
		echo "failed to determine generated GPG key fingerprint" >&2
		exit 1
	fi
	run_as_desktop git config --global user.email "$email"
	run_as_desktop git config --global user.name "Secrets Dispatcher VM"

	if ! run_as_desktop gopass stores 2>/dev/null | grep -q '^root'; then
		if ! run_as_desktop timeout 120s gopass --yes init "$fingerprint"; then
			run_as_desktop timeout 120s gopass init "$fingerprint"
		fi
	fi

	verify_gopass_secret_service_direct
}

verify_gopass_secret_service_direct() {
	log "verifying gopass-secret-service directly with secret-tool"
	cat >/tmp/gopass-secret-service-direct-check.sh <<'EOF_DIRECT'
#!/usr/bin/env bash
set -euo pipefail
service_bin=$1
log_file=${TMPDIR:-/tmp}/gopass-secret-service-direct.log
"$service_bin" >"$log_file" 2>&1 &
service_pid=$!
cleanup() {
	local status=$?
	if [ "$status" -ne 0 ]; then
		printf 'gopass-secret-service direct-check log:\n' >&2
		cat "$log_file" >&2 || true
	fi
	kill "$service_pid" >/dev/null 2>&1 || true
	wait "$service_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT
for _ in $(seq 1 100); do
	if busctl --user --timeout=2 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.freedesktop.secrets 2>/dev/null | grep -q 'b true'; then
		break
	fi
	if ! kill -0 "$service_pid" >/dev/null 2>&1; then
		cat "$log_file" >&2 || true
		exit 1
	fi
	sleep 0.1
done
busctl --user --timeout=5 call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.freedesktop.secrets | grep -q 'b true'
for _ in $(seq 1 100); do
	if busctl --user --timeout=2 call org.freedesktop.secrets /org/freedesktop/secrets/aliases/default org.freedesktop.DBus.Properties GetAll s org.freedesktop.Secret.Collection >/dev/null 2>&1; then
		break
	fi
	if ! kill -0 "$service_pid" >/dev/null 2>&1; then
		cat "$log_file" >&2 || true
		exit 1
	fi
	sleep 0.1
done
busctl --user --timeout=5 call org.freedesktop.secrets /org/freedesktop/secrets/aliases/default org.freedesktop.DBus.Properties GetAll s org.freedesktop.Secret.Collection >/dev/null
printf 'vm-secret\n' | secret-tool store --label='VM gopass check' vm-backend gopass
got=$(secret-tool lookup vm-backend gopass)
if [ "$got" != vm-secret ]; then
	echo "secret-tool lookup returned '$got'" >&2
	exit 1
fi
EOF_DIRECT
	chmod 0755 /tmp/gopass-secret-service-direct-check.sh
	run_as_desktop dbus-run-session -- /tmp/gopass-secret-service-direct-check.sh "$GOPASS_SECRET_SERVICE_BIN"
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

assert_local_topology() {
	local cfg unit_dir unit
	cfg="/home/$DESKTOP_USER/.config/secrets-dispatcher/config.yaml"
	unit_dir="/home/$DESKTOP_USER/.config/systemd/user"
	if [ ! -f "$cfg" ]; then
		log "config not found: $cfg"
		return 1
	fi
	if ! grep -q 'type: managed' "$cfg"; then
		log "local mode config does not use managed upstream"
		cat "$cfg" || true
		return 1
	fi
	case "$BACKEND" in
	gnome-keyring)
		if ! grep -q 'backend_command: .*gnome-keyring-daemon' "$cfg"; then
			log "local mode config does not use GNOME Keyring backend command"
			cat "$cfg" || true
			return 1
		fi
		;;
	gopass)
		if ! grep -q 'backend_command: .*gopass-secret-service' "$cfg"; then
			log "local mode config does not use gopass backend command"
			cat "$cfg" || true
			return 1
		fi
		;;
	esac
	if ! grep -q 'type: session_bus' "$cfg"; then
		log "local mode config does not expose the session bus downstream"
		cat "$cfg" || true
		return 1
	fi
	if grep -Eq 'keyring-dispatcher-backend|secrets-dispatcher-bus|backend_bus' "$cfg"; then
		log "local mode config contains stale public backend details"
		cat "$cfg" || true
		return 1
	fi
	for unit in secrets-dispatcher-bus.socket secrets-dispatcher-bus.service secrets-dispatcher-backend.service; do
		if [ -e "$unit_dir/$unit" ]; then
			log "stale split-backend unit exists: $unit_dir/$unit"
			return 1
		fi
	done
}

install_local_mode() {
	local backend_args=()
	case "$BACKEND" in
	gnome-keyring)
		backend_args=(--backend gnome-keyring)
		;;
	gopass)
		backend_args=(--backend "$GOPASS_SECRET_SERVICE_BIN")
		;;
	*)
		echo "unsupported BACKEND=$BACKEND (want gnome-keyring or gopass)" >&2
		exit 2
		;;
	esac
	log "installing service mode=$MODE backend=$BACKEND"
	run_as_desktop "$BINARY" service install --start --mode "$MODE" "${backend_args[@]}"
	wait_for_user_unit secrets-dispatcher.service
	wait_for_secret_service_owner
	assert_secret_service_owned_by_dispatcher
	assert_local_topology
	assert_tcp_api_requires_auth
	log "service mode=$MODE backend=$BACKEND installed successfully"
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

install_secure_local_polkit_rule() {
	if ! command -v pkaction >/dev/null 2>&1 && ! command -v pkcheck >/dev/null 2>&1; then
		log "polkit tools not found; secure-local user-start may require interactive authorization"
		return 0
	fi
	mkdir -p /etc/polkit-1/rules.d
	cat >/etc/polkit-1/rules.d/49-secrets-dispatcher-secure-local-test.rules <<EOF_POLKIT
polkit.addRule(function(action, subject) {
    if (subject.user !== "$DESKTOP_USER") {
        return polkit.Result.NOT_HANDLED;
    }
    if (action.id === "org.freedesktop.systemd1.manage-units") {
        var unit = action.lookup("unit");
        if (unit && unit.indexOf("secrets-dispatcher-secure@") === 0) {
            return polkit.Result.YES;
        }
    }
    if (action.id === "org.freedesktop.systemd1.manage-unit-files") {
        return polkit.Result.YES;
    }
    return polkit.Result.NOT_HANDLED;
});
EOF_POLKIT
	systemctl reload polkit >/dev/null 2>&1 || systemctl restart polkit >/dev/null 2>&1 || true
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

install_secure_local_user_mode() {
	local unit=secrets-dispatcher-secure@$DESKTOP_USER.service
	if [ "$BACKEND" != gnome-keyring ]; then
		echo "secure-local-user currently supports BACKEND=gnome-keyring only" >&2
		exit 2
	fi
	log "provisioning secure-local mode"
	"$BINARY" provision --mode secure-local --user "$DESKTOP_USER" --binary "$BINARY"
	write_secure_trusted_config
	"$BINARY" provision --mode secure-local --user "$DESKTOP_USER" --binary "$BINARY" --check
	assert_secure_provisioning_artifacts
	install_secure_local_polkit_rule

	log "installing and starting secure-local via desktop user service install"
	run_as_desktop "$BINARY" service install --mode secure-local --start
	for _ in $(seq 1 60); do
		if systemctl is-active --quiet "$unit"; then
			break
		fi
		sleep 1
	done
	systemctl is-active --quiet "$unit" || fail_with_unit_logs "$unit"
	wait_for_secret_service_owner || fail_with_unit_logs "$unit"
	assert_secret_service_owned_by_desktop_user
	assert_secret_service_responds
	assert_secure_api_requires_auth
	log "secure-local user install mode started successfully"
}

cleanup_secure_local() {
	local unit=secrets-dispatcher-secure@$DESKTOP_USER.service
	systemctl disable --now "$unit" >/dev/null 2>&1 || true
}

log "guest distro: $(. /etc/os-release && printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-unknown}")"
log "scenario=$SCENARIO mode=$MODE backend=$BACKEND gnome_profile=$GNOME_PROFILE desktop_user=$DESKTOP_USER"

install_packages
ensure_desktop_user
start_user_session_bus

if [ "$BACKEND" = gopass ]; then
	prepare_gopass_backend
fi

"$BINARY" version >/dev/null

case "$SCENARIO" in
local|full)
	MODE=$SCENARIO
	install_local_mode
	;;
secure-local-user)
	install_secure_local_user_mode
	cleanup_secure_local
	;;
*)
	echo "unsupported SCENARIO=$SCENARIO (want local, full, or secure-local-user)" >&2
	exit 2
	;;
esac

log "smoke test complete"
