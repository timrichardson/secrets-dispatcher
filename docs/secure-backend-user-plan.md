# Secure Backend User Mode Plan

## Goal

Add a new optional mode that keeps the existing user-mode deployments working, while providing a stronger local security boundary for users who install root-managed components.

In this mode:

- The public Secret Service endpoint remains `org.freedesktop.secrets` on each desktop user's session D-Bus.
- Secrets Dispatcher remains the policy/UI proxy seen by desktop apps.
- A pluggable Secret Service backend runs as a separate backend Linux user, not as the desktop user.
- GNOME Keyring is the first and only planned backend implementation for the initial version.
- Root-managed systemd starts the backend, creates the private backend transport, and keeps the backend connection capability inside the trusted broker it starts.
- The trusted broker will eventually prompt the logged-in desktop user when the backend needs human authentication to unlock.
- Multiple logged-in users get isolated per-user proxy/backend instances.

## Non-Goals

- Do not remove existing `remote`, `local`, or `full` modes.
- Do not require every user to install privileged components.
- Do not implement a new secret store in the first iteration.
- Do not fork GNOME Keyring unless the CLI unlock path proves insufficient.
- Do not rely on hidden socket paths as the security boundary.
- Do not make secure mode init-system neutral; systemd is an explicit dependency.
- Do not decide in this plan whether the proxy directly unlocks the backend or mediates a backend-originated unlock challenge. That is a Phase 5 design spike.

## Platform Assumptions

Secure mode is intentionally scoped to modern Linux desktops with:

- systemd system manager and user/session integration.
- logind-style runtime directories under `/run/user/<uid>`.
- a user session D-Bus for desktop apps.
- Secret Service clients using `org.freedesktop.secrets`.
- Unix domain sockets and kernel peer credentials (`SO_PEERCRED`).
- A modern kernel with standard cross-UID process and filesystem protections.

This is expected to be portable across mainstream systemd Linux distributions, but it is not intended to support non-systemd init systems in secure mode.

## Threat Model

Primary attacker: malicious code running as the desktop Linux user, for example `tim`.

The new mode should prevent that attacker from directly:

- Reading or modifying backend keyring files.
- Reading backend process memory.
- Using the backend user's unlocked GNOME Keyring directly.
- Connecting to a generally available backend D-Bus socket.
- Replacing the proxy binary or root-managed system units.

The new mode does not fully prevent that attacker from:

- Making requests through the public Secret Service proxy.
- Tricking the human user into approving a request.
- Interacting with the desktop session as the logged-in user.
- Reading secret values after they are delivered to an approved same-UID app.
- Attacking user-owned browser/session state.
- Denying service by killing user processes or flooding requests.

## Security Boundaries

Backend UID separation is the hard boundary. It protects the backend user's keyring files, backend process memory, and private backend D-Bus from direct access by malware running as the desktop Linux user.

The trusted broker is a mediation boundary, not a kernel-enforced chokepoint for every same-UID action on the desktop session. It provides policy checks, audit history, rate limiting, and blast-radius reduction by forwarding only approved operations to the backend. If a secret is approved and delivered to a desktop-user process, same-UID malware may still be able to read it from that process or its user-owned state.

Owning `org.freedesktop.secrets` on the desktop user's session bus is a compatibility rendezvous. A same-UID attacker may be able to race the public bus name, unmask public activation, or present a competing service. Those attacks are denial-of-service, phishing, or alternate-empty-keyring risks; they must not grant direct access to the backend user's store.

Caller attribution from D-Bus sender names, process IDs, `/proc`, command names, working directories, and systemd unit names is advisory under a same-UID attacker. Durable rules may use these signals to reduce prompts, but they should not be documented as strong identity proofs unless the rule also relies on a stronger trust root.

## Mode Name

Use a new explicit install mode, proposed name:

`secure-local`

Existing modes continue to mean what they mean today:

- `remote`: proxy remote/socket clients to existing session Secret Service.
- `local`: proxy session bus clients to a same-user local backend.
- `full`: both session bus and socket clients with same-user backend.
- `secure-local`: proxy session bus clients to a root-managed, separate-user GNOME Keyring backend.

## High-Level Topology

For each desktop user:

```text
desktop apps
  -> user session D-Bus org.freedesktop.secrets
  -> Secrets Dispatcher trusted broker running from root-managed systemd
  -> private backend D-Bus
  -> Secret Service backend running as backend user

desktop UI agent running as desktop user
  -> notifications/browser integration
  -> narrow IPC to trusted broker
```

The public side remains compatible with ordinary Secret Service clients. The private side is not reachable through a filesystem socket or inherited file descriptor that arbitrary desktop-user processes can open or steal.

## Per-User Isolation

Although the role can be described as "the secrets-backend user", multi-user support is safest with one backend identity/state per desktop user.

Default account naming should reuse the existing companion pattern:

```text
desktop user: tim
backend user: secrets-tim
backend home: /var/lib/secret-companion/tim
```

This avoids a single shared backend account internally separating Alice and Bob's secrets. A shared backend user can be supported later only if it has strict per-UID store separation and authorization checks.

## Root-Managed Launch Model

Do not make a backend socket readable/connectable by the desktop user. If `tim` can open the socket using normal filesystem permissions, any process running as `tim` can open it too.

Use a root-owned systemd template service, for example:

```text
secrets-dispatcher-secure@<desktop-user>.service
```

The service runs a root-owned launcher command, proposed:

```text
secrets-dispatcher secure-launch --user <desktop-user>
```

The launcher is responsible for:

1. Looking up the desktop user UID and backend user UID.
2. Verifying the desktop session bus exists at `/run/user/<uid>/bus`.
3. Creating a private runtime directory not searchable by the desktop user.
4. Starting a private backend D-Bus daemon as the backend user.
5. Starting `gnome-keyring-daemon --foreground --components=secrets` as the backend user on that private bus.
6. Running the trusted broker/proxy outside the desktop user's UID boundary.
7. Connecting the trusted broker to the desktop user's session bus and the private backend bus.
8. Keeping approval/auth state in root-owned secure-local state.
9. Supervising all child processes and shutting them down together.

This keeps the trust decision in root-owned unit files and root-owned executable paths, not in a request that arbitrary desktop-user processes can make.

## Trusted Broker

The trusted broker owns the secure-local mediation boundary.

Responsibilities:

- Run as root or a dedicated non-desktop service user under a root-owned systemd unit.
- Connect to the desktop user's session bus and own `org.freedesktop.secrets`.
- Connect to the private backend bus without passing that connection or socket path to the desktop user.
- Hold approval/auth state in root-owned secure-local state, not under the desktop user's home directory.
- Forward Secret Service calls after policy decisions.
- Eventually expose a narrow UI/control API to a desktop-user UI agent without granting backend transport access.
- Avoid loopback TCP for secure-local approval/admin control; use a Unix socket and peer-credential-aware authorization.

The desktop-user process is only a UI agent. It may show notifications and open a browser, but it must not hold backend bus access or be the sole authority for approval decisions.

The initial broker keeps the API Unix-socket-only and root-owned while the UI-agent authorization path is incomplete. The socket is `/run/secrets-dispatcher/<desktop-user>/api.sock`, the server requires `SO_PEERCRED` UID 0 before normal API auth, and no loopback TCP listener is opened by default. That is less usable, but it avoids creating a localhost bearer-token approval bypass.

Before allowing a desktop-user UI agent to approve, deny, unlock, or mutate rules, secure mode needs an explicit authorization design such as Polkit, PAM, or another user-presence check. A desktop-user-readable bearer token is not sufficient for the same-UID malware threat model.

## Backend Provider Contract

Secure mode should treat the backend as pluggable even though the first implementation is GNOME Keyring.

A secure backend provider must supply:

- A Secret Service-compatible D-Bus service that can run on a private backend bus.
- A non-interactive start path suitable for a systemd/root launcher.
- Per-desktop-user state under the backend user's home or state directory.
- A way to determine whether the backend is locked or cannot currently return secret material.
- A non-interactive unlock mechanism that a privileged helper can invoke after the desktop user authenticates through the proxy UI.
- A way for the proxy to retry or complete the original Secret Service operation once the backend is unlocked.
- No requirement for arbitrary desktop-user processes to access the backend user's runtime directory, D-Bus bus, keyring files, or agent sockets.

Provider implementation should be modeled as a small interface in code, with GNOME Keyring as the first implementation. Future providers could include gopass or a purpose-built backend if they meet the same contract.

## GNOME Keyring Backend

GNOME Keyring is the first backend provider.

Run GNOME Keyring as the backend user:

```text
DBUS_SESSION_BUS_ADDRESS=<private backend bus>
HOME=<backend home>
XDG_RUNTIME_DIR=<private backend runtime>
gnome-keyring-daemon --foreground --components=secrets --control-directory=<private control dir>
```

The backend user's keyring files live under the backend home, not the desktop user's home.

Existing desktop-user GNOME Keyring secrets require migration.

GNOME Keyring appears to provide the required non-interactive unlock primitive:

```text
gnome-keyring-daemon --unlock
```

It can read the keyring password from stdin. The initial implementation should verify this works against the same backend user's daemon/control directory in secure mode before relying on it.

Possible locked-state signals to test:

- Secret Service item/collection `Locked` properties.
- `SearchItems` returning matching items in the locked set.
- `Unlock` returning a prompt object.
- `GetSecrets` failing or returning no secret for locked items.

The proxy should use provider-specific locked-state detection to distinguish "policy denied", "secret not found", "backend error", and "backend needs unlock".

## Unlock Flow

Secure mode requires that the selected backend provider have a non-interactive unlock mechanism. For GNOME Keyring, the candidate mechanism is:

```text
gnome-keyring-daemon --unlock
```

It can read the keyring password from stdin. This means we may not need to patch GNOME Keyring for the first version, but the exact unlock integration is still an implementation detail to prove.

Required behavior:

- The proxy can detect that the backend is locked or needs authentication.
- The proxy can present a human authentication prompt to the logged-in desktop user.
- After successful authentication, the backend is unlocked enough for the proxy to obtain the requested secret through the normal Secret Service path.
- The original app never receives backend transport access or unlock credentials.

Candidate implementation A: proxy-initiated unlock helper.

1. Proxy forwards an allowed request to the backend.
2. Proxy detects that the backend is locked.
3. Proxy creates a high-priority unlock request in the Web UI and desktop notification.
4. User enters the backend keyring password into the proxy UI.
5. Trusted broker invokes the provider's non-interactive unlock as the backend user.
6. Trusted broker returns success/failure to the UI agent.
7. Trusted broker retries the original operation or asks the app to retry, depending on Secret Service semantics.

Candidate implementation B: backend-originated unlock challenge.

1. Backend/provider bridge reports an unlock challenge to the proxy.
2. Proxy prompts the desktop user.
3. Proxy sends the response to the bridge/helper.
4. Bridge/helper unlocks the backend and resumes or allows retry.

This may better match backends that can emit a structured authentication challenge, but GNOME Keyring may not make this easy without relying on its CLI unlock path.

Security requirements:

- Do not log the password.
- Do not put the password in argv or environment.
- Pass via stdin or a pipe only.
- Keep backend bus descriptors and decrypted secret transport out of desktop-user processes.
- Keep unlock attempts rate-limited.
- Make unlock UI visibly different from ordinary approval prompts.

Open question: whether the proxy should ever store the backend keyring password for retries. Default should be no.

Open question: whether the proxy should directly initiate unlock, or only respond to a backend/provider unlock challenge. Phase 5 must test GNOME Keyring behavior before choosing.

## Public Session Bus Ownership

The trusted broker connects to the desktop user's session bus at `/run/user/<uid>/bus` and owns `org.freedesktop.secrets` there. It does not need to run as the desktop user and must not pass backend bus access to a desktop-user helper.

The root-owned systemd service must start only after the user's session bus exists, and stop when the user session ends unless lingering secure mode is explicitly requested.

## Installation Commands

Add a separate privileged provisioning command rather than overloading existing user-mode install behavior.

Proposed commands:

```bash
sudo secrets-dispatcher provision secure-backend --user tim --backend gnome-keyring
secrets-dispatcher service install --mode secure-local --start
```

Or, if keeping the current `provision` shape:

```bash
sudo secrets-dispatcher provision --mode secure-local --user tim
```

The non-root `service install --mode secure-local` should fail with clear instructions if root provisioning is missing.

## Systemd Artifacts

Root-owned artifacts:

- `/usr/lib/systemd/system/secrets-dispatcher-secure@.service`
- Optional target: `secrets-dispatcher-secure@.target`
- Root-owned binary path, for example `/usr/local/bin/secrets-dispatcher` or packaged `/usr/bin/secrets-dispatcher`
- Backend user account and home/state directory.
- D-Bus activation mask for public GNOME Keyring in the desktop user session.

Avoid user-writable paths in root-owned units.

The existing user unit install paths remain unchanged for non-secure modes.

## Migration From Existing GNOME Keyring

Secure mode uses a different backend user and therefore a different keyring store.

Migration should be explicit:

1. Run old/current GNOME Keyring as the desktop user.
2. Unlock it normally.
3. Enumerate collections/items through Secret Service.
4. Prompt before export/import.
5. Write items to the secure backend via the proxy/backend path.
6. Preserve label, attributes, collection, and secret value.
7. Report unsupported metadata.

Do not silently copy or chown the desktop user's keyring files into the backend account.

## Backward Compatibility

- Existing config files remain valid.
- Existing `remote/local/full` install modes continue to work.
- Existing API, Web UI, CLI, approval rules, and history remain compatible.
- Secure mode adds new config fields and command paths only when selected.

## Testing Strategy

Secure mode has to be tested in layers. Not every malicious same-user behavior can be made deterministic in CI, but the main bypass classes are testable.

### CI-Safe Unit Tests

- Config accepts `secure-local` provider selection without changing existing non-secure upstream/downstream modes.
- Existing `remote/local/full` configs remain valid.
- Systemd unit templates never reference user-writable binary paths.
- Provisioning templates render per-user backend names and state directories correctly.
- Secure-local API uses a Unix socket with peer-credential UID checks and no default loopback TCP listener.
- Provider interface maps locked/unlocked/error states distinctly.
- Unlock helper command construction never places passwords in argv or environment.
- Rule hardening still rejects broad durable rules and unsafe multi-item approvals.

### Unprivileged Integration Tests

- Use private `dbus-daemon` instances and fake Secret Service backends.
- Verify the trusted broker can connect to private frontend/backend D-Bus instances without passing backend FDs to desktop-user processes.
- Verify secure-local uses root-owned state for auth cookies, saved rules, temporary rules, and history.
- Verify the proxy detects a simulated locked backend and creates the expected unlock request.
- Verify the proxy retries or resumes after a simulated successful unlock.

### Root/Systemd Integration Tests

These should run in a VM, privileged container with systemd, or local manual test target, not normal CI by default.

- Provision two desktop users and two backend users.
- Start `secrets-dispatcher-secure@user1` and `secrets-dispatcher-secure@user2` simultaneously.
- Verify each proxy owns `org.freedesktop.secrets` only on its own user session bus.
- Verify each backend runs as the matching backend user.
- Verify backend state files are unreadable and unwritable by the desktop user.
- Verify arbitrary desktop-user processes cannot connect to the backend transport even if they know candidate paths.
- Verify arbitrary desktop-user processes cannot call the secure-local approval/admin API until the UI-agent authorization path is implemented.
- Verify a request can be approved, forwarded, unlocked, and completed through GNOME Keyring.
- Verify uninstall/rollback restores non-secure modes and public GNOME Keyring activation state.

### Adversarial Tests

Automate where feasible under the root/systemd test harness:

- Malicious desktop-user process scans `/run`, `/run/user/<uid>`, `/tmp`, config files, and unit files for backend addresses and tries to connect.
- Malicious desktop-user process tries to claim `org.freedesktop.secrets` before and after the secure proxy starts.
- Malicious desktop-user process tries to call the backend Secret Service API directly and must fail.
- Malicious desktop-user process tries to invoke the unlock helper directly and must fail.
- Malicious desktop-user process tries to alter root-owned units and binary paths and must fail.

### Manual/Platform Tests

Some behaviors are distribution- and desktop-dependent and should be captured in a manual compatibility matrix:

- GNOME Keyring `--unlock` works with the secure backend user's daemon/control directory.
- Locked-state detection works across GNOME Keyring versions.
- systemd/logind lifecycle behaves correctly on login/logout.
- SELinux/AppArmor policies on Fedora/Ubuntu derivatives do not block the intended confined IPC.
- `dbus-daemon` and `dbus-broker` based systems both behave as expected.

## Backend Provider Configuration

Secure mode should require an explicit provider in provisioning/config, even while only GNOME Keyring is implemented.

Example trusted policy snippet:

```yaml
serve:
  secure_backend:
    provider: gnome-keyring
```

Provider-specific fields can be added later under `secure_backend.provider_config` or similar. The initial GNOME Keyring provider should keep configuration minimal until behavior is verified.

## Implementation Phases

### Phase 1: Config and Planning Scaffolding

- Add `secure-local` as a recognized install mode.
- Add secure backend provider config with `gnome-keyring` as the only accepted provider.
- Add tests for config validation, install-mode parsing, and provider selection.

### Phase 2: Trusted Broker

- Add trusted broker support that connects to the desktop user's session bus and private backend bus.
- Keep backend bus access in the trusted broker process, not in a desktop-user child.
- Store secure-local auth/rules/history under root-owned state.
- Keep existing `session_bus`, `socket`, and `sockets` behavior unchanged.
- Add tests proving secure-local does not create a desktop-user proxy child with backend FD access.

### Phase 3: Root Launcher Prototype

- Add `secure-launch --user <desktop-user>` subcommand.
- Root-only preflight checks.
- Start private backend D-Bus daemon as backend user.
- Start the selected backend provider as backend user; initially only GNOME Keyring.
- Run the trusted broker/proxy outside the desktop user's UID boundary.
- Supervise all children.
- Integration test as much as possible without root; isolate privileged calls behind testable interfaces.

### Phase 4: Provisioning

- Extend `internal/companion` or create `internal/securebackend` for root provisioning.
- Create per-desktop-user backend account, default `secrets-<user>`.
- Create backend home/runtime/state directories.
- Install root-owned systemd template units.
- Add `provision --check` coverage for secure-local artifacts.

### Phase 5: Unlock UI and Helper

- Add a distinct unlock request type in approval/API/Web UI.
- Spike GNOME Keyring locked-state detection and `--unlock` behavior in secure mode.
- Choose proxy-initiated unlock helper or backend-originated unlock challenge based on the spike.
- If using helper unlock, helper runs `gnome-keyring-daemon --unlock` as backend user with password on stdin.
- Rate-limit failures.
- Avoid password logging and argv/env exposure.

### Phase 6: Multi-User Lifecycle

- Start per-user secure instances on login.
- Stop per-user instances on logout unless configured to linger.
- Ensure Alice and Bob get separate backend users, stores, and trusted broker instances.
- Add status/check commands that show per-user instance health.

### Phase 7: Migration Tool

- Add explicit migration command from current desktop-user Secret Service to secure backend.
- Preserve metadata where supported.
- Dry-run and report counts before writing.

### Phase 8: Hardening

- Root-owned units never reference user-writable binaries.
- Set proxy non-dumpable in secure mode.
- Add systemd hardening options where compatible.
- Ensure backend bus path/address is not logged or written to user-readable config.
- Verify arbitrary desktop-user processes cannot connect to backend transport.
- Add documentation of residual same-user risks.

## Branch Dependencies

This feature should incorporate the principles from the hidden backend work:

- No stable backend socket in user unit files.
- No backend bus address in user config or logs.
- GNOME public activation remains masked in local interception modes.

It should also incorporate saved-rule hardening before being considered secure enough to recommend:

- Durable `gpg_sign` rules rejected or properly constrained.
- Multi-item approval rules require all items to match.
- Generated durable rules prefer executable path constraints.

## Acceptance Criteria

- Existing modes pass current tests unchanged.
- `secure-local` can be provisioned and started for one user.
- Secure mode requires an explicit backend provider, with `gnome-keyring` implemented first.
- `org.freedesktop.secrets` is owned by the secure proxy on that user's session bus.
- The selected backend provider runs as the backend user.
- Backend bus/socket is not connectable by arbitrary processes running as the desktop user.
- Secure-local approval/admin API is not exposed on loopback TCP and rejects non-root Unix-socket peers until a stronger UI-agent authorization path exists.
- The proxy can detect locked backend state and request human authentication.
- The backend can be unlocked through the chosen provider mechanism without putting the password in argv/env/logs.
- After unlock, the proxy can complete or retry the original Secret Service request and obtain the requested secret through the normal backend path.
- Multiple users can run isolated instances simultaneously.
- CI-safe unit and unprivileged integration tests cover config, provider selection, trusted broker behavior, and locked-state handling.
- Root/systemd integration tests cover per-user provisioning, backend-user isolation, and malicious direct-connect attempts.
- Documentation clearly states what this protects and what same-user malware can still do.
