package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func savedRuleTestRequest(attrs map[string]string) *Request {
	return &Request{
		ID:   "req-1",
		Type: RequestTypeGetSecret,
		Items: []ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Label:      "GitHub token",
			Attributes: attrs,
		}},
		SenderInfo: savedRuleSender("/usr/bin/gh"),
	}
}

func savedRuleSender(exe string) SenderInfo {
	return SenderInfo{
		UnitName:     "gh",
		ProcessChain: []ProcessInfo{{Name: "gh", PID: 1, Exe: exe}},
	}
}

func TestSavedApprovalRule_PersistsAndMatchesAfterReload(t *testing.T) {
	store := NewFileSavedApprovalRuleStore(t.TempDir())
	mgr := NewManager(ManagerConfig{
		Timeout:         20 * time.Millisecond,
		HistoryMax:      10,
		SavedRulesStore: store,
	})
	mgr.AddHistoryEntry(HistoryEntry{Request: savedRuleTestRequest(map[string]string{"service": "github"}), Resolution: ResolutionApproved})

	if _, err := mgr.CreateSavedApprovalRuleFromRequest("req-1"); err != nil {
		t.Fatalf("CreateSavedApprovalRuleFromRequest failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	reloaded := NewManager(ManagerConfig{
		Timeout:            20 * time.Millisecond,
		HistoryMax:         10,
		SavedApprovalRules: loaded,
		SavedRulesStore:    store,
	})

	autoApproved, err := reloaded.RequireApproval(context.Background(), "client", savedRuleTestRequest(map[string]string{"service": "github"}).Items, "", RequestTypeGetSecret, nil, savedRuleSender("/usr/bin/gh"))
	if err != nil {
		t.Fatalf("RequireApproval returned error: %v", err)
	}
	if !autoApproved {
		t.Fatal("expected saved rule to auto-approve")
	}
	history := reloaded.History()
	if len(history) != 1 {
		t.Fatalf("history count = %d, want 1", len(history))
	}
	info := history[0].Request.AutoApproval
	if info == nil || info.Source != "saved_rule" || info.RuleName == "" || info.RuleID == "" {
		t.Fatalf("auto approval attribution = %#v, want saved rule with name and ID", info)
	}
}

func TestPersistAutoApproveRule_SavesAndRemovesTemporaryRule(t *testing.T) {
	store := NewFileSavedApprovalRuleStore(t.TempDir())
	mgr := NewManager(ManagerConfig{
		Timeout:             20 * time.Millisecond,
		HistoryMax:          10,
		AutoApproveDuration: time.Minute,
		SavedRulesStore:     store,
	})

	tempID := mgr.AddAutoApproveRule(savedRuleTestRequest(map[string]string{"service": "github"}))
	if _, err := mgr.PersistAutoApproveRule(tempID); err != nil {
		t.Fatalf("PersistAutoApproveRule failed: %v", err)
	}
	if got := mgr.ListAutoApproveRules(); len(got) != 0 {
		t.Fatalf("temporary rule still present: %#v", got)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("saved rules count = %d, want 1", len(loaded))
	}
}

func TestSavedApprovalRule_EscapesLiteralGlobMetacharacters(t *testing.T) {
	mgr := NewManager(ManagerConfig{Timeout: 20 * time.Millisecond, HistoryMax: 10})
	mgr.AddHistoryEntry(HistoryEntry{Request: savedRuleTestRequest(map[string]string{"service": "gh[prod]*"}), Resolution: ResolutionApproved})
	if _, err := mgr.CreateSavedApprovalRuleFromRequest("req-1"); err != nil {
		t.Fatalf("CreateSavedApprovalRuleFromRequest failed: %v", err)
	}

	if rule := mgr.CheckSavedApprovalRules(savedRuleSender("/usr/bin/gh"), savedRuleTestRequest(map[string]string{"service": "gh[prod]*"}).Items, RequestTypeGetSecret, nil); rule == nil {
		t.Fatal("expected exact literal value to match")
	}
	if rule := mgr.CheckSavedApprovalRules(savedRuleSender("/usr/bin/gh"), savedRuleTestRequest(map[string]string{"service": "ghp"}).Items, RequestTypeGetSecret, nil); rule != nil {
		t.Fatalf("unexpected wildcard match: %#v", rule)
	}
}

func TestSavedApprovalRule_DoesNotOverrideConfigDeny(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Timeout:    20 * time.Millisecond,
		HistoryMax: 10,
		TrustRules: []TrustRule{{
			Name:         "deny-gh",
			Action:       "deny",
			RequestTypes: []string{"get_secret"},
			Process:      &ProcessMatcher{Unit: "gh"},
		}},
	})
	mgr.AddHistoryEntry(HistoryEntry{Request: savedRuleTestRequest(map[string]string{"service": "github"}), Resolution: ResolutionApproved})
	if _, err := mgr.CreateSavedApprovalRuleFromRequest("req-1"); err != nil {
		t.Fatalf("CreateSavedApprovalRuleFromRequest failed: %v", err)
	}

	autoApproved, err := mgr.RequireApproval(context.Background(), "client", savedRuleTestRequest(map[string]string{"service": "github"}).Items, "", RequestTypeGetSecret, nil, savedRuleSender("/usr/bin/gh"))
	if !errors.Is(err, ErrDeniedByRule) {
		t.Fatalf("RequireApproval error = %v, want ErrDeniedByRule", err)
	}
	if !autoApproved {
		t.Fatal("rule-denied request should be resolved without prompting")
	}
}

func TestSavedApprovalRule_GeneratedRuleUsesExecutablePath(t *testing.T) {
	mgr := NewManager(ManagerConfig{Timeout: 20 * time.Millisecond, HistoryMax: 10})
	mgr.AddHistoryEntry(HistoryEntry{Request: savedRuleTestRequest(map[string]string{"service": "github"}), Resolution: ResolutionApproved})
	rule, err := mgr.CreateSavedApprovalRuleFromRequest("req-1")
	if err != nil {
		t.Fatalf("CreateSavedApprovalRuleFromRequest failed: %v", err)
	}
	if rule.Process == nil || rule.Process.Exe != "/usr/bin/gh" || rule.Process.Unit != "" || rule.Process.Name != "" {
		t.Fatalf("generated process matcher = %#v, want executable path only", rule.Process)
	}
	if matched := mgr.CheckSavedApprovalRules(savedRuleSender("/tmp/gh"), savedRuleTestRequest(map[string]string{"service": "github"}).Items, RequestTypeGetSecret, nil); matched != nil {
		t.Fatalf("spoofed process name with different executable matched saved rule: %#v", matched)
	}
}

func TestSavedApprovalRule_MultiItemRequiresEveryItemToMatch(t *testing.T) {
	mgr := NewManager(ManagerConfig{Timeout: 20 * time.Millisecond, HistoryMax: 10})
	mgr.AddHistoryEntry(HistoryEntry{Request: savedRuleTestRequest(map[string]string{"service": "github"}), Resolution: ResolutionApproved})
	if _, err := mgr.CreateSavedApprovalRuleFromRequest("req-1"); err != nil {
		t.Fatalf("CreateSavedApprovalRuleFromRequest failed: %v", err)
	}

	items := []ItemInfo{
		{Path: "/org/freedesktop/secrets/collection/login/item1", Attributes: map[string]string{"service": "github"}},
		{Path: "/org/freedesktop/secrets/collection/login/item2", Attributes: map[string]string{"service": "bank"}},
	}
	if rule := mgr.CheckSavedApprovalRules(savedRuleSender("/usr/bin/gh"), items, RequestTypeGetSecret, nil); rule != nil {
		t.Fatalf("mixed multi-item request matched saved approval rule: %#v", rule)
	}
}

func TestSavedApprovalRule_GPGSignUnsupported(t *testing.T) {
	mgr := NewManager(ManagerConfig{Timeout: 20 * time.Millisecond, HistoryMax: 10})
	_, err := mgr.CreateSavedApprovalRule(SavedApprovalRule{
		RequestTypes: []string{string(RequestTypeGPGSign)},
		Process:      &ProcessMatcher{Exe: "/usr/bin/git"},
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("CreateSavedApprovalRule error = %v, want ErrInvalidRule", err)
	}

	mgr.AddHistoryEntry(HistoryEntry{Request: &Request{
		ID:          "gpg-1",
		Type:        RequestTypeGPGSign,
		GPGSignInfo: sampleGPGSignInfo(),
		SenderInfo:  savedRuleSender("/usr/bin/git"),
	}, Resolution: ResolutionApproved})
	_, err = mgr.CreateSavedApprovalRuleFromRequest("gpg-1")
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("CreateSavedApprovalRuleFromRequest error = %v, want ErrInvalidRule", err)
	}

	legacy := NewManager(ManagerConfig{SavedApprovalRules: []SavedApprovalRule{{
		ID:           "legacy-gpg",
		Enabled:      true,
		RequestTypes: []string{string(RequestTypeGPGSign)},
		Process:      &ProcessMatcher{Exe: "/usr/bin/git"},
	}}})
	if rule := legacy.CheckSavedApprovalRules(savedRuleSender("/usr/bin/git"), nil, RequestTypeGPGSign, nil); rule != nil {
		t.Fatalf("legacy gpg_sign saved rule matched: %#v", rule)
	}
}
