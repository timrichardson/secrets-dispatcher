#!/usr/bin/env bash
set -euo pipefail

DISTRO=${DISTRO:-unknown}
BACKEND=${BACKEND:-gopass}
GNOME_PROFILE=${GNOME_PROFILE:-minimal}
DESKTOP_USER=${DESKTOP_USER:-sdtest}
BINARY=${BINARY:-/usr/local/bin/secrets-dispatcher}
APPROVAL_RULE_TEMP_DURATION=${APPROVAL_RULE_TEMP_DURATION:-4s}
APPROVAL_RULE_EXPIRY_WAIT=${APPROVAL_RULE_EXPIRY_WAIT:-6}
GOPASS_SOURCE=${GOPASS_SOURCE:-github.com/gopasspw/gopass@latest}
GOPASS_SECRET_SERVICE_SOURCE=${GOPASS_SECRET_SERVICE_SOURCE:-github.com/nikicat/gopass-secret-service/cmd/gopass-secret@latest}
GOPASS_SECRET_SERVICE_BIN=${GOPASS_SECRET_SERVICE_BIN:-/usr/local/bin/gopass-secret-service}

export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

FAKE_NOTIFY_LOG=/tmp/secrets-dispatcher-fake-notifications.log
FAKE_NOTIFY_STDOUT=/tmp/secrets-dispatcher-fake-notifications.stdout
FAKE_NOTIFY_PID=

log() {
	printf '[vm-approval-rules] %s\n' "$*"
}

fail_with_user_logs() {
	local unit=${1:-secrets-dispatcher.service}
	log "user unit status for $unit"
	run_as_desktop systemctl --user status "$unit" --no-pager || true
	log "user unit journal for $unit"
	run_as_desktop journalctl --user -u "$unit" --no-pager -n 200 || true
	print_notification_logs
	exit 1
}

print_notification_logs() {
	if [ -f "$FAKE_NOTIFY_LOG" ]; then
		log "fake notification log"
		cat "$FAKE_NOTIFY_LOG" || true
	fi
	if [ -f "$FAKE_NOTIFY_STDOUT" ]; then
		log "fake notification stdout/stderr"
		cat "$FAKE_NOTIFY_STDOUT" || true
	fi
}

cleanup() {
	set +e
	if [ -n "${FAKE_NOTIFY_PID:-}" ]; then
		kill "$FAKE_NOTIFY_PID" >/dev/null 2>&1 || true
		wait "$FAKE_NOTIFY_PID" >/dev/null 2>&1 || true
	fi
	if id "$DESKTOP_USER" >/dev/null 2>&1; then
		run_as_desktop systemctl --user stop secrets-dispatcher.service >/dev/null 2>&1 || true
		run_as_desktop systemctl --user stop secrets-dispatcher-backend.service >/dev/null 2>&1 || true
		run_as_desktop systemctl --user stop secrets-dispatcher-bus.socket >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

install_packages_ubuntu() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends \
		ca-certificates curl sudo dbus dbus-user-session dbus-x11 \
		gnome-keyring libsecret-tools systemd-container procps \
		python3-dbus python3-gi gnupg git golang-go
	apt-get install -y --no-install-recommends gopass || true
	if [ "$GNOME_PROFILE" = desktop ]; then
		apt-get install -y --no-install-recommends ubuntu-desktop-minimal || \
			apt-get install -y --no-install-recommends gnome-session gdm3
	fi
}

install_packages_fedora() {
	dnf install -y \
		ca-certificates curl sudo dbus-daemon dbus-tools \
		gnome-keyring libsecret systemd-container procps-ng shadow-utils \
		python3-dbus python3-gobject gnupg2 git golang
	dnf install -y gopass || true
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
	fail_with_user_logs "$unit"
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

wait_for_secret_service_owner() {
	for _ in $(seq 1 60); do
		if secret_service_has_owner; then
			return 0
		fi
		sleep 1
	done
	log "org.freedesktop.secrets owner did not appear"
	run_as_desktop busctl --user --no-pager list || true
	fail_with_user_logs secrets-dispatcher.service
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

	seed_gopass_secret_service
}

seed_gopass_secret_service() {
	log "seeding gopass Secret Service backend"
	cat >/tmp/gopass-secret-service-seed.sh <<'EOF_SEED'
#!/usr/bin/env bash
set -euo pipefail
service_bin=$1
log_file=${TMPDIR:-/tmp}/gopass-secret-service-seed.log
"$service_bin" >"$log_file" 2>&1 &
service_pid=$!
cleanup() {
	local status=$?
	if [ "$status" -ne 0 ]; then
		printf 'gopass-secret-service seed log:\n' >&2
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
printf 'primary-secret\n' | secret-tool store --label='VM primary secret' sd-vm primary
printf 'secondary-secret\n' | secret-tool store --label='VM secondary secret' sd-vm secondary
got=$(secret-tool lookup sd-vm primary)
if [ "$got" != primary-secret ]; then
	echo "primary seed lookup returned '$got'" >&2
	exit 1
fi
got=$(secret-tool lookup sd-vm secondary)
if [ "$got" != secondary-secret ]; then
	echo "secondary seed lookup returned '$got'" >&2
	exit 1
fi
EOF_SEED
	chmod 0755 /tmp/gopass-secret-service-seed.sh
	run_as_desktop dbus-run-session -- /tmp/gopass-secret-service-seed.sh "$GOPASS_SECRET_SERVICE_BIN"
}

install_fake_notifier() {
	cat >/tmp/fake-notifications.py <<'EOF_NOTIFY'
#!/usr/bin/env python3
import json
import os
import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

IFACE = "org.freedesktop.Notifications"
PATH = "/org/freedesktop/Notifications"


class Notifications(dbus.service.Object):
    def __init__(self, bus, log_path, action_plan, delay_ms):
        self.bus = bus
        self.log_path = log_path
        self.action_plan = action_plan
        self.delay_ms = delay_ms
        self.next_id = 0
        super().__init__(bus, PATH)

    def log(self, event, **fields):
        record = {"event": event, **fields}
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            fh.flush()

    @dbus.service.method(IFACE, in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app_name, replaces_id, app_icon, summary, body, actions, hints, expire_timeout):
        self.next_id += 1
        notification_id = self.next_id
        action_list = [str(a) for a in actions]
        self.log(
            "notify",
            id=notification_id,
            summary=str(summary),
            body=str(body),
            actions=action_list,
            expire_timeout=int(expire_timeout),
        )
        action_key = self.choose_action(action_list)
        if action_key:
            GLib.timeout_add(self.delay_ms, self.invoke_action, notification_id, action_key)
        return dbus.UInt32(notification_id)

    def choose_action(self, action_list):
        if "save_rule" in action_list:
            return "save_rule"
        if not self.action_plan:
            return None
        return self.action_plan.pop(0)

    def invoke_action(self, notification_id, action_key):
        self.log("action", id=int(notification_id), action=action_key)
        self.ActionInvoked(dbus.UInt32(notification_id), action_key)
        return False

    @dbus.service.method(IFACE, in_signature="u", out_signature="")
    def CloseNotification(self, notification_id):
        self.log("close", id=int(notification_id))

    @dbus.service.method(IFACE, in_signature="", out_signature="as")
    def GetCapabilities(self):
        return ["actions", "body", "persistence"]

    @dbus.service.method(IFACE, in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return ("secrets-dispatcher-test", "secrets-dispatcher", "1.0", "1.2")

    @dbus.service.signal(IFACE, signature="us")
    def ActionInvoked(self, notification_id, action_key):
        pass

    @dbus.service.signal(IFACE, signature="uu")
    def NotificationClosed(self, notification_id, reason):
        pass


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    log_path = os.environ.get("FAKE_NOTIFY_LOG", "/tmp/secrets-dispatcher-fake-notifications.log")
    action_plan = [a for a in os.environ.get("FAKE_NOTIFY_ACTIONS", "approve_and_auto_approve,deny").split(",") if a]
    delay_ms = int(os.environ.get("FAKE_NOTIFY_DELAY_MS", "200"))
    name = dbus.service.BusName(IFACE, bus=bus, do_not_queue=True)
    notifications = Notifications(bus, log_path, action_plan, delay_ms)
    print("fake notification server ready", flush=True)
    _ = (name, notifications)
    GLib.MainLoop().run()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"fake notification server failed: {exc}", file=sys.stderr, flush=True)
        raise
EOF_NOTIFY
	chmod 0755 /tmp/fake-notifications.py
}

start_fake_notifier() {
	install_fake_notifier
	rm -f "$FAKE_NOTIFY_LOG" "$FAKE_NOTIFY_STDOUT"
	run_as_desktop env \
		FAKE_NOTIFY_LOG="$FAKE_NOTIFY_LOG" \
		FAKE_NOTIFY_ACTIONS="approve_and_auto_approve,deny" \
		FAKE_NOTIFY_DELAY_MS=200 \
		python3 /tmp/fake-notifications.py >"$FAKE_NOTIFY_STDOUT" 2>&1 &
	FAKE_NOTIFY_PID=$!
	for _ in $(seq 1 100); do
		if run_as_desktop busctl --user --timeout=2 call \
			org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner \
			s org.freedesktop.Notifications 2>/dev/null | grep -q 'b true'; then
			log "fake notification server owns org.freedesktop.Notifications"
			return 0
		fi
		if ! kill -0 "$FAKE_NOTIFY_PID" >/dev/null 2>&1; then
			print_notification_logs
			exit 1
		fi
		sleep 0.1
	done
	print_notification_logs
	echo "fake notification server did not acquire org.freedesktop.Notifications" >&2
	exit 1
}

write_dispatcher_config() {
	local cfg_dir cfg_file
	cfg_dir="/home/$DESKTOP_USER/.config/secrets-dispatcher"
	cfg_file="$cfg_dir/config.yaml"
	mkdir -p "$cfg_dir"
	cat >"$cfg_file" <<EOF_CONFIG
listen: "127.0.0.1:8484"
serve:
  log_level: debug
  timeout: 20s
  history_limit: 200
  notifications: true
  notification_delay: 0s
  approval_window: 1s
  auto_approve_duration: $APPROVAL_RULE_TEMP_DURATION
EOF_CONFIG
	chown -R "$DESKTOP_USER:$DESKTOP_USER" "$cfg_dir"
	chmod 0600 "$cfg_file"
}

install_dispatcher_local_mode() {
	log "installing secrets-dispatcher local mode with gopass backend"
	write_dispatcher_config
	run_as_desktop "$BINARY" service install --start --mode local --backend "$GOPASS_SECRET_SERVICE_BIN"
	wait_for_user_unit secrets-dispatcher-bus.socket
	wait_for_user_unit secrets-dispatcher-backend.service
	wait_for_user_unit secrets-dispatcher.service
	wait_for_secret_service_owner
	assert_secret_service_owned_by_dispatcher
}

notification_count() {
	if [ ! -f "$FAKE_NOTIFY_LOG" ]; then
		printf '0\n'
		return
	fi
	grep -c '"event": "notify"' "$FAKE_NOTIFY_LOG" || true
}

assert_lookup_value() {
	local key=$1
	local expected=$2
	local got
	got=$(run_as_desktop timeout 30s secret-tool lookup sd-vm "$key")
	if [ "$got" != "$expected" ]; then
		log "secret-tool lookup sd-vm $key returned '$got', want '$expected'"
		return 1
	fi
}

wait_for_saved_rule() {
	local rules_file=/home/$DESKTOP_USER/.local/state/secrets-dispatcher/approval-rules.json
	for _ in $(seq 1 100); do
		if [ -s "$rules_file" ] && grep -q '"get_secret"' "$rules_file"; then
			if [ "$(stat -c '%a' "$rules_file")" != 600 ]; then
				log "unexpected saved rule file mode: $(stat -c '%a' "$rules_file")"
				return 1
			fi
			return 0
		fi
		sleep 0.2
	done
	log "saved approval rule file was not created: $rules_file"
	if [ -e "$rules_file" ]; then
		cat "$rules_file" || true
	fi
	print_notification_logs
	return 1
}

assert_no_new_notifications_for_lookup() {
	local key=$1
	local expected=$2
	local before after
	before=$(notification_count)
	assert_lookup_value "$key" "$expected"
	sleep 0.5
	after=$(notification_count)
	if [ "$after" != "$before" ]; then
		log "lookup for $key generated a notification after saved rule should have matched (before=$before after=$after)"
		print_notification_logs
		return 1
	fi
}

assert_secondary_secret_still_prompts() {
	local before after out
	before=$(notification_count)
	if out=$(run_as_desktop timeout 30s secret-tool lookup sd-vm secondary 2>/tmp/secondary-lookup.err); then
		log "secondary lookup unexpectedly succeeded: $out"
		print_notification_logs
		return 1
	fi
	after=$(notification_count)
	if [ "$after" -le "$before" ]; then
		log "secondary lookup did not prompt despite not matching the saved rule"
		cat /tmp/secondary-lookup.err || true
		print_notification_logs
		return 1
	fi
}

run_saved_rule_flow() {
	log "triggering first lookup; fake notification will approve similar and save the follow-up rule"
	assert_lookup_value primary primary-secret
	wait_for_saved_rule

	log "waiting ${APPROVAL_RULE_EXPIRY_WAIT}s for temporary approval rule to expire"
	sleep "$APPROVAL_RULE_EXPIRY_WAIT"

	log "verifying saved rule still auto-approves in the current daemon session"
	assert_no_new_notifications_for_lookup primary primary-secret

	log "restarting dispatcher and verifying saved rule is loaded from disk"
	run_as_desktop systemctl --user restart secrets-dispatcher.service
	wait_for_user_unit secrets-dispatcher.service
	wait_for_secret_service_owner
	assert_secret_service_owned_by_dispatcher
	assert_no_new_notifications_for_lookup primary primary-secret

	log "verifying a different secret still prompts and can be denied"
	assert_secondary_secret_still_prompts
}

log "guest distro: $(. /etc/os-release && printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-unknown}")"
log "backend=$BACKEND gnome_profile=$GNOME_PROFILE desktop_user=$DESKTOP_USER temp_duration=$APPROVAL_RULE_TEMP_DURATION expiry_wait=$APPROVAL_RULE_EXPIRY_WAIT"

if [ "$BACKEND" != gopass ]; then
	echo "unsupported BACKEND=$BACKEND (want gopass)" >&2
	exit 2
fi

install_packages
ensure_desktop_user
start_user_session_bus
prepare_gopass_backend
start_fake_notifier
install_dispatcher_local_mode
run_saved_rule_flow

log "approval-rule VM integration test complete"
