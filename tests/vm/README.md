# VM Smoke Tests

This harness boots disposable Ubuntu or Fedora cloud VMs with libvirt/QEMU,
copies the locally built `secrets-dispatcher` binary into the guest, and
exercises service installation against a real systemd user manager and D-Bus
session bus.

The smoke tests cover:

- Ubuntu local install with a dispatcher-supervised private GNOME Keyring backend.
- Fedora local install with a dispatcher-supervised private GNOME Keyring backend.
- Ubuntu local install with a dispatcher-supervised private gopass backend.
- Fedora local install with a dispatcher-supervised private gopass backend.
- Secure-local provisioning plus the desktop-user `service install --mode secure-local --start` path.

## Host Dependencies

The runner checks for required host commands and tries to install missing
dependencies automatically on Ubuntu/Debian and Fedora hosts when passwordless
`sudo` is available. Set `VM_INSTALL_HOST_DEPS=0` to disable that behavior.

Ubuntu host:

```bash
sudo apt install qemu-kvm libvirt-daemon-system virtinst cloud-image-utils qemu-utils openssh-client curl
sudo usermod -aG libvirt,kvm "$USER"
```

Fedora host:

```bash
sudo dnf install @virtualization virt-install libvirt-daemon-kvm cloud-utils qemu-img openssh-clients curl
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"
```

Log out and back in after changing group membership.

## Usage

Run the default smoke test:

```bash
make vm-test
```

Run the full VM matrix:

```bash
make vm-test-all
```

Run individual local-backend smoke tests:

```bash
make vm-test-ubuntu-gnome
make vm-test-fedora-gnome
make vm-test-ubuntu-gopass
make vm-test-fedora-gopass
```

Run secure-local user-install smoke tests:

```bash
make vm-test-ubuntu-secure-local-user
make vm-test-fedora-secure-local-user
```

Compatibility aliases:

```bash
make vm-test-ubuntu
make vm-test-fedora
make vm-test-ubuntu-normal
make vm-test-ubuntu-secure-local
```

Useful environment variables:

- `DISTRO`: `ubuntu` or `fedora`.
- `SCENARIO`: `local`, `full`, or `secure-local-user`; `normal` aliases to `local`, and `secure-local` aliases to `secure-local-user`.
- `BACKEND`: `gnome-keyring` or `gopass` for local/full scenarios.
- `MODE`: fallback scenario value for older invocations. Defaults to `local`.
- `DESKTOP_USER`: desktop user created inside the VM. Defaults to `sdtest`.
- `GNOME_PROFILE`: `desktop` installs fuller GNOME packages; `minimal` installs only the Secret Service/session-bus packages. Defaults to `desktop`.
- `KEEP_VM=1`: leave the VM running for debugging.
- `VM_NAME`: override the libvirt domain name.
- `VM_DIR`: override the per-run working directory; defaults to `.vm/<name>`.
- `VM_IMAGE_CACHE`: override downloaded cloud-image cache; defaults to `${XDG_CACHE_HOME:-~/.cache}/secrets-dispatcher/vm-images`.
- `UBUNTU_IMAGE_URL`: override the Ubuntu image URL.
- `FEDORA_IMAGE_URL`: override the Fedora image URL.
- `VM_INSTALL_HOST_DEPS`: `1` tries to install missing host commands with `apt-get` or `dnf`; `0` only reports missing dependencies. Defaults to `1`.
- `GOPASS_SOURCE`: Go package used when `gopass` is not available from distro packages; defaults to `github.com/gopasspw/gopass@latest`.
- `GOPASS_SECRET_SERVICE_SOURCE`: Go package used when `gopass-secret-service` is not available; defaults to `github.com/nikicat/gopass-secret-service/cmd/gopass-secret@latest`.
- `GOPASS_SECRET_SERVICE_BIN`: backend command path used for `BACKEND=gopass`; defaults to `/usr/local/bin/gopass-secret-service`.

## Local Scope

The `local` and `full` scenarios perform these checks inside the VM:

- Install `secrets-dispatcher` with `service install --start --mode <mode> --backend <backend>`.
- For `BACKEND=gopass`, create a disposable no-passphrase GPG key and gopass store, install `gopass-secret-service`, and verify it directly with `secret-tool` under `dbus-run-session`.
- Verify `secrets-dispatcher.service` is active.
- Verify `org.freedesktop.secrets` is owned by the `secrets-dispatcher` binary on the desktop user's session bus.
- Verify the generated config uses `serve.upstream.type: managed` and the expected backend command.
- Verify stale split-backend user units are not installed.
- Verify the normal HTTP API endpoint is reachable and requires auth.

## Secure-Local Scope

The `secure-local-user` scenario performs these checks inside the VM:

- Run `provision --mode secure-local --user <user> --binary /usr/local/bin/secrets-dispatcher` as root.
- Write the root-owned trusted config used by `secure-launch` at `/etc/secrets-dispatcher/secure/<user>.yaml`.
- Run `provision --check`.
- Verify the backend user, backend home permissions, and root systemd unit.
- Install and start secure-local by running `service install --mode secure-local --start` as the desktop user.
- Verify `secrets-dispatcher-secure@<user>.service` becomes active.
- Verify `org.freedesktop.secrets` is owned by the `secrets-dispatcher` binary on the desktop user's session bus.
- Verify the secure Unix-socket API endpoint is reachable and requires auth.

This is a deployment smoke test. It does not attempt a full interactive approval
flow or unlock a GNOME Keyring collection.
