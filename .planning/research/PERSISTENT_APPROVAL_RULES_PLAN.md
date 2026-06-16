# Persistent Approval Rules Plan

Branch: `feature/persistent-approval-rules`
Status: plan only
Date: 2026-06-16

## Goal

Add a durable, user-managed approval-rule feature that lets a desktop user:

- Turn an existing temporary `Approve similar` rule into a saved rule.
- Create a saved rule from a pending or recently cancelled/approved request.
- Review, edit, disable, and delete saved approval rules.
- Keep temporary auto-approve rules available for short retry windows.

## Current State

- `approval.AutoApproveRule` is temporary and in-memory only.
- Temporary rules are created by `ApproveAndAutoApprove` / `AddAutoApproveRule` and expire after `serve.auto_approve_duration`, defaulting to 2 minutes.
- The REST API can list/create/delete temporary rules via `/api/v1/auto-approve`, but cannot edit or persist them.
- The web UI already receives `auto_approve_rules` over the websocket and can display/delete active temporary rules.
- `serve.rules` are persistent config-defined trust rules, but they are static config policy, not user-managed desktop rules.
- The desktop notification has `Approve`, `Approve similar`, and `Deny`; `Approve similar` currently creates only a temporary in-memory rule.

## Product Decisions

- Saved approval rules are separate from config `serve.rules`.
- Saved approval rules are stored in the state directory, not written back into `config.yaml`.
- First implementation supports persistent `approve` rules only. `deny` and `ignore` remain config-only policy rules.
- Generated rules are exact-match by default. Any wildcard/glob widening must be an explicit edit in the rule editor.
- Desktop notifications provide one-click entry points; full review/edit/delete happens in the local authenticated web UI opened from the desktop.
- Temporary rules remain visible and removable, but saved rules get their own management surface.

## UX Plan

### Desktop Notification

- Keep the existing security prompt actions: `Approve`, `Approve similar`, `Deny`.
- After `Approve similar` creates a temporary rule, show a follow-up notification such as `Temporary approval active`.
- Follow-up actions:
- `Save rule`: persist the just-created temporary rule.
- `Review rules`: open the web UI rules view.
- The follow-up body must summarize scope: process, request type, collection, and attributes/search attributes.
- If the notification server drops extra actions or the action cannot be correlated, fall back to opening the web UI rules view.

### Web UI

- Add a persistent `Rules` or `Approval Rules` section that is visible even when no rules exist.
- Split the section into:
- `Temporary rules`: active `Approve similar` rules with expiry countdown and delete/persist actions.
- `Saved approval rules`: durable user-managed approve rules with edit, disable/enable, and delete actions.
- `Config trust rules`: read-only display of `serve.rules` so users understand precedence.
- Add `Save as rule` actions to pending request cards and eligible history entries.
- Add an edit dialog with fields for name, enabled state, request types, process matcher, secret matcher, and search attributes.
- Show a conservative match summary before saving: `Process + request type + collection + attributes`.

## Backend Design

### Data Model

Add a saved-rule model separate from `AutoApproveRule`, for example:

```go
type SavedApprovalRule struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    Enabled   bool      `json:"enabled"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Match     RuleMatch `json:"match"`
}
```

`RuleMatch` should reuse the existing matcher concepts where possible:

- Request types.
- Process matcher: name, exe, cwd, unit.
- Secret matcher: collection, label, attributes.
- Search attributes.

Generated rules should escape literal values before storing any glob-capable matcher. Editing can expose wildcard behavior explicitly.

### Storage

- Store saved rules under the resolved state directory, e.g. `$STATE_DIR/approval-rules.json`.
- Use a schema wrapper with a version field to allow migrations.
- Create state directories with private permissions.
- Write atomically using temp file + fsync + rename, with file mode `0600`.
- Treat unreadable or invalid rule storage as a startup error unless an explicit recovery path is added.

### Manager Integration

- Extend `ManagerConfig` with loaded saved rules or a rule store.
- Add manager methods:
- `ListSavedApprovalRules()`.
- `CreateSavedApprovalRuleFromRequest(requestID string)`.
- `PersistAutoApproveRule(ruleID string)`.
- `CreateSavedApprovalRule(rule SavedApprovalRule)`.
- `UpdateSavedApprovalRule(id string, patch/update)`.
- `RemoveSavedApprovalRule(id string)`.
- Match saved rules in normal Secret Service approval flow and in the GPG-sign flow.
- Preserve cache behavior: the short approval cache remains separate from temporary and saved rules.
- Ensure config `deny` / `ignore` rules cannot be bypassed by a saved approval rule.

Recommended precedence:

1. Disabled manager mode.
2. Hard config policy: `deny` / `ignore`.
3. Short approval cache for eligible read operations.
4. Temporary auto-approve rules.
5. Saved approval rules.
6. Config `approve` rules.
7. Manual prompt.

### API

Keep `/api/v1/auto-approve` for temporary rules and add saved-rule endpoints:

- `GET /api/v1/approval-rules` lists saved rules.
- `POST /api/v1/approval-rules` creates a saved rule from an explicit payload.
- `POST /api/v1/approval-rules/from-request` creates a saved rule from a pending or historical request ID.
- `POST /api/v1/auto-approve/{id}/persist` persists a temporary rule.
- `PUT /api/v1/approval-rules/{id}` replaces/updates a saved rule.
- `DELETE /api/v1/approval-rules/{id}` deletes a saved rule.

All endpoints stay behind the existing web/API auth.

### Websocket

- Add saved rules to the initial snapshot as `approval_rules`.
- Add events: `approval_rule_added`, `approval_rule_updated`, `approval_rule_removed`.
- Keep existing `auto_approve_rule_added` / `auto_approve_rule_removed` for temporary rules.

## Implementation Steps

1. Add saved-rule model, matcher conversion helpers, and JSON rule store.
2. Load saved rules at service startup and pass them into the approval manager.
3. Add manager methods for list/create/update/delete/persist and unified matching.
4. Add REST endpoints and websocket snapshot/events.
5. Add desktop notification follow-up flow for persisting a just-created temporary rule.
6. Add web UI rule management: list, persist, edit, enable/disable, delete.
7. Update docs to distinguish temporary auto-approve rules, saved approval rules, and config trust rules.
8. Add tests and run the existing Go/frontend verification commands.

## Test Plan

### Go Unit Tests

- Saved rules load from state and survive manager/service restart.
- Persisting a temporary rule writes state and emits an add/update event.
- Editing a saved rule changes matching behavior and emits an update event.
- Deleting a saved rule removes it from state and future matching.
- Generated rules match exact literal values, including glob metacharacters.
- Config `deny` and `ignore` rules take precedence over saved approval rules.
- GPG-sign requests consult saved approval rules where temporary rules are currently consulted.

### API Tests

- Authenticated list/create/update/delete/persist paths work.
- Bad rule IDs and invalid payloads return 400/404 as appropriate.
- Method routing preserves existing `/api/v1/auto-approve` behavior.
- Websocket snapshots and rule events include saved rules.

### Frontend Tests

- Rules section is visible with no rules.
- Temporary rules can be persisted from the UI.
- Saved rules can be edited, disabled/enabled, and deleted.
- Scope summaries render process, request type, collection, and attributes clearly.

### Desktop Notification Tests

- `Approve similar` still creates a temporary rule.
- A follow-up `Save rule` action persists the created temporary rule.
- `Review rules` opens the rules view.
- Unknown/stale notification actions fail closed without approving anything.

## Risks

- Persisting a generated rule too broadly can become a long-lived secret-access grant. Default generation must be conservative.
- Existing temporary rule matching uses `InvokerName`; saved rules should expose clearer process matching and avoid silently widening scope.
- Notification action support differs by desktop environment, so the web UI must be the reliable management surface.
- Editing `config.yaml` from the UI would risk comments, user formatting, and config race conditions; state-file storage avoids that.

## Acceptance Criteria

- A user can approve similar temporarily from a desktop notification and then persist that temporary rule from the desktop flow.
- Saved rules remain after service restart.
- The web UI can review, edit, disable/enable, and delete saved approval rules.
- Temporary rules and saved rules are visually distinct.
- Config trust rules remain visible and read-only in the UI.
- No saved approval rule can override a config `deny` or `ignore` policy.
