# Ubuntu VM Smoke Tests

This harness boots a disposable Ubuntu cloud VM with libvirt/QEMU, copies the
locally built `secrets-dispatcher` binary into the guest, and exercises service
installation against a real systemd user manager and D-Bus session bus.

The secure-local scenario checks both paths this branch must preserve:

- normal user-mode local install with GNOME Keyring
- secure-local provisioning and root-managed secure service startup

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

Run the secure-local branch smoke test:

```bash
make vm-test-ubuntu-secure-local
```

Run only the normal local install smoke test:

```bash
make vm-test-ubuntu-normal
```

`make vm-test` and `make vm-test-ubuntu` default to the secure-local scenario.

Useful environment variables:

- `SCENARIO`: `secure-local` or `normal`.
- `DESKTOP_USER`: desktop user created inside the VM. Defaults to `sdtest`.
- `GNOME_PROFILE`: `desktop` installs fuller Ubuntu GNOME packages; `minimal`
  installs only the Secret Service/session-bus packages. Defaults to `desktop`.
- `KEEP_VM=1`: leave the VM running for debugging.
- `VM_NAME`: override the libvirt domain name.
- `VM_DIR`: override the per-run working directory; defaults to `.vm/<name>`.
- `VM_IMAGE_CACHE`: override downloaded cloud-image cache; defaults to
  `${XDG_CACHE_HOME:-~/.cache}/secrets-dispatcher/vm-images`.
- `UBUNTU_IMAGE_URL`: override the Ubuntu image URL.
- `VM_INSTALL_HOST_DEPS`: `1` tries to install missing host commands with
  `apt-get` or `dnf`; `0` only reports missing dependencies. Defaults to `1`.

## Secure-Local Scope

The secure-local scenario performs these checks inside the VM:

- Installs normal local mode with `service install --mode local --backend gnome-keyring --start`.
- Verifies `secrets-dispatcher.service` is active.
- Verifies `org.freedesktop.secrets` is owned on the desktop user's session bus.
- Verifies the normal HTTP API endpoint is reachable and requires auth.
- Uninstalls the normal user-mode service.
- Runs `provision --mode secure-local --user <user> --binary /usr/local/bin/secrets-dispatcher`.
- Writes the root-owned trusted config used by `secure-launch` at
  `/etc/secrets-dispatcher/secure/<user>.yaml`.
- Runs `provision --check`.
- Verifies the backend user, backend home permissions, and root systemd unit.
- Runs `service install --mode secure-local` as the desktop user.
- Starts `secrets-dispatcher-secure@<user>.service` as root.
- Verifies `org.freedesktop.secrets` is owned on the desktop user's session bus.
- Verifies the secure Unix-socket API endpoint is reachable and requires auth.

This is a deployment smoke test. It does not attempt a full interactive approval
flow or unlock a GNOME Keyring collection.
