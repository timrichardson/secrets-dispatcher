<script lang="ts">
  import type { HistoryEntry as HistoryEntryType, PendingRequest, AutoApproveRule, SavedApprovalRule } from "./types";
  import RequestOverview from "./RequestOverview.svelte";
  import PropsTable from "./PropsTable.svelte";

  interface Props {
    entry: HistoryEntryType;
    count?: number;
    tick: number;
    autoApproveRules: AutoApproveRule[];
    approvalRules: SavedApprovalRule[];
    formatTime: (dateString: string) => string;
    toggleTimeFormat: () => void;
    onAutoApprove: (requestId: string) => void;
    onSaveRule: (requestId: string) => void;
  }

  let { entry, count = 1, tick, autoApproveRules, approvalRules, formatTime, toggleTimeFormat, onAutoApprove, onSaveRule }: Props = $props();

  function resolutionClass(resolution: string): string {
    switch (resolution) {
      case "approved":
        return "resolution-approved";
      case "denied":
        return "resolution-denied";
      case "auto_approved":
        return "resolution-auto-approved";
      case "ignored":
        return "resolution-ignored";
      default:
        return "resolution-other";
    }
  }

  function extractCollection(itemPath: string): string {
    for (const prefix of [
      "/org/freedesktop/secrets/collection/",
      "/org/freedesktop/secrets/aliases/",
    ]) {
      if (itemPath.startsWith(prefix)) {
        const rest = itemPath.slice(prefix.length);
        const slash = rest.indexOf("/");
        return slash >= 0 ? rest.slice(0, slash) : rest;
      }
    }
    return "";
  }

  function historyEntryProps(req: PendingRequest): { collection?: string; attributes?: Record<string, string> } {
    const collection = req.items.length > 0 ? extractCollection(req.items[0].path) || undefined : undefined;
    let attributes: Record<string, string> | undefined;
    if (req.type === "search" && req.search_attributes && Object.keys(req.search_attributes).length > 0) {
      attributes = req.search_attributes;
    } else if (req.type !== "gpg_sign" && req.items.length > 0 && req.items[0].attributes && Object.keys(req.items[0].attributes).length > 0) {
      attributes = req.items[0].attributes;
    }
    return { collection, attributes };
  }

  function attributesEqual(a: Record<string, string> | undefined, b: Record<string, string> | undefined): boolean {
    const aa = a ?? {};
    const bb = b ?? {};
    const keysA = Object.keys(aa);
    const keysB = Object.keys(bb);
    if (keysA.length !== keysB.length) return false;
    return keysA.every(k => aa[k] === bb[k]);
  }

  function hasMatchingRule(entry: HistoryEntryType): boolean {
    const req = entry.request;
    const invoker = req.sender_info?.invoker_name ?? "";
    const collection = req.items.length > 0 ? extractCollection(req.items[0].path) : "";
    const attrs = req.items.length > 0 ? req.items[0].attributes : undefined;
    return autoApproveRules.some(r =>
      r.invoker_name === invoker &&
      r.request_type === req.type &&
      r.collection === collection &&
      attributesEqual(r.attributes, attrs)
    );
  }

  function sourceLabel(source: string): string {
    switch (source) {
      case "config_rule": return "config rule";
      case "temporary_rule": return "temporary rule";
      case "saved_rule": return "saved rule";
      case "trusted_signer": return "trusted signer";
      default: return source.replaceAll("_", " ");
    }
  }

  function decisionAttributionLabel(entry: HistoryEntryType): string {
    const info = entry.request.attribution;
    if (!info) return "";
    const name = info.rule_name || info.rule_id || sourceLabel(info.source);
    const suffix = info.rule_id && info.rule_name ? ` (${info.rule_id.slice(0, 8)})` : "";
    return `${sourceLabel(info.source)}: ${name}${suffix}`;
  }

  function decisionAttributionPrefix(entry: HistoryEntryType): string {
    switch (entry.resolution) {
      case "denied": return "Denied by";
      case "ignored": return "Ignored by";
      case "auto_approved": return "Auto-approved by";
      default: return "Resolved by";
    }
  }

  function hasMatchingSavedRule(entry: HistoryEntryType): boolean {
    const req = entry.request;
    const collection = req.items.length > 0 ? extractCollection(req.items[0].path) : "";
    const attrs = req.type === "search" ? req.search_attributes : (req.items.length > 0 ? req.items[0].attributes : undefined);
    return approvalRules.some(r =>
      r.enabled &&
      r.request_types.includes(req.type) &&
      processMatcherMatches(r.process, req.sender_info) &&
      (r.secret?.collection ?? "") === collection &&
      attributesEqual(r.secret?.attributes ?? r.search_attributes, attrs)
    );
  }

  function processMatcherMatches(process: SavedApprovalRule["process"], sender: HistoryEntryType["request"]["sender_info"]): boolean {
    if (!process || !sender) return false;
    if (process.exe && sender.process_chain?.some(p => p.exe === process.exe)) return true;
    if (process.name && sender.process_chain?.some(p => p.name === process.name)) return true;
    return Boolean(process.unit && process.unit === sender.systemd_unit);
  }

  function canSaveRule(entry: HistoryEntryType): boolean {
    return entry.request.type !== "gpg_sign" && (entry.resolution === "approved" || entry.resolution === "cancelled" || entry.resolution === "auto_approved");
  }
</script>

<li class="history-entry">
  <div class="history-entry-header">
    <div class="history-entry-badges">
      <span class="history-type history-type--{entry.request.type}">
        {#if entry.request.type === "gpg_sign"}
          GPG Sign
        {:else if entry.request.type === "search"}
          Search
        {:else if entry.request.type === "delete"}
          Delete
        {:else if entry.request.type === "write"}
          Write
        {:else if entry.request.type === "unlock"}
          Unlock
        {:else if entry.request.type === "ssh_sign"}
          SSH Sign
        {:else}
          Secret
        {/if}
      </span>
      <span class="history-resolution {resolutionClass(entry.resolution)}">{entry.resolution}</span>
      {#if count > 1}
        <span class="history-count">&times;{count}</span>
      {/if}
      <span class="history-request-id" title={entry.request.id}>{entry.request.id.slice(0, 8)}</span>
    </div>
    <button class="history-time clickable" onclick={toggleTimeFormat}>{void tick, formatTime(entry.resolved_at)}</button>
  </div>
  <RequestOverview request={entry.request} />
  <PropsTable {...historyEntryProps(entry.request)} />
  {#if entry.request.attribution}
    <div class="decision-attribution-source">{decisionAttributionPrefix(entry)} {decisionAttributionLabel(entry)}</div>
  {/if}
  {#if entry.resolution === "cancelled"}
    <button
      class="btn-auto-approve"
      title="Create or refresh a temporary rule for future requests like this"
      onclick={() => onAutoApprove(entry.request.id)}
    >{hasMatchingRule(entry) ? "Refresh similar rule" : "Allow future similar"}</button>
  {/if}
  {#if canSaveRule(entry)}
    <button
      class="btn-auto-approve"
      title="Create a saved approval rule for future requests like this"
      onclick={() => onSaveRule(entry.request.id)}
    >{hasMatchingSavedRule(entry) ? "Saved rule active" : "Save as approval rule"}</button>
  {/if}
</li>

<style>
  .history-entry {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 12px;
    background-color: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    margin-bottom: 8px;
  }

  .history-entry:last-child {
    margin-bottom: 0;
  }

  .history-entry-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .history-entry-badges {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .history-resolution {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: var(--radius-sm);
  }

  .history-type {
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: var(--radius-sm);
    color: var(--color-text-muted);
    background-color: var(--color-bg);
    border: 1px solid var(--color-border);
  }

  .history-type--gpg_sign {
    color: var(--color-gpg-sign);
    border-color: var(--color-gpg-sign);
    background-color: var(--color-gpg-sign-bg);
  }

  .history-type--delete,
  .history-type--write {
    color: var(--color-danger);
    border-color: var(--color-danger);
    background-color: color-mix(in srgb, var(--color-danger) 10%, transparent);
  }

  .resolution-approved {
    color: var(--color-success);
    background-color: rgba(34, 197, 94, 0.1);
  }

  .resolution-denied {
    color: var(--color-danger);
    background-color: rgba(239, 68, 68, 0.1);
  }

  .resolution-auto-approved {
    color: var(--color-primary);
    background-color: rgba(59, 130, 246, 0.1);
  }

  .resolution-ignored {
    color: var(--color-text-muted);
    background-color: var(--color-bg);
  }

  .resolution-other {
    color: var(--color-text-muted);
    background-color: var(--color-bg);
  }

  .history-count {
    font-size: 12px;
    font-weight: 600;
    color: var(--color-primary);
    background-color: rgba(59, 130, 246, 0.1);
    padding: 2px 6px;
    border-radius: var(--radius-sm);
  }

  .history-request-id {
    font-size: 11px;
    font-family: ui-monospace, "SF Mono", Monaco, monospace;
    color: var(--color-text-muted);
    opacity: 0.6;
  }

  .history-time {
    font-size: 12px;
    color: var(--color-text-muted);
  }

  .history-time.clickable {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    cursor: pointer;
  }

  .history-time.clickable:hover {
    color: var(--color-text);
    text-decoration: underline;
  }

  .history-entry-details {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .history-items {
    font-size: 14px;
    font-weight: 500;
    color: var(--color-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .decision-attribution-source {
    font-size: 12px;
    color: var(--color-primary);
    background-color: rgba(59, 130, 246, 0.08);
    border: 1px solid rgba(59, 130, 246, 0.18);
    border-radius: var(--radius-sm);
    padding: 4px 8px;
  }

  .btn-auto-approve {
    margin-top: 6px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 500;
    color: var(--color-primary);
    background: transparent;
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  .btn-auto-approve:hover {
    background-color: rgba(59, 130, 246, 0.1);
  }
</style>
