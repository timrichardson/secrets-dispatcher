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
		SenderInfo: SenderInfo{UnitName: "gh"},
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

	autoApproved, err := reloaded.RequireApproval(context.Background(), "client", savedRuleTestRequest(map[string]string{"service": "github"}).Items, "", RequestTypeGetSecret, nil, SenderInfo{UnitName: "gh"})
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
	attr := history[0].Request.Attribution
	if attr == nil {
		t.Fatal("expected saved rule attribution")
	}
	if attr.Source != "saved_rule" || attr.Action != "approve" || attr.RuleID == "" {
		t.Fatalf("unexpected attribution: %+v", attr)
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

	if rule := mgr.CheckSavedApprovalRules(SenderInfo{UnitName: "gh"}, savedRuleTestRequest(map[string]string{"service": "gh[prod]*"}).Items, RequestTypeGetSecret, nil); rule == nil {
		t.Fatal("expected exact literal value to match")
	}
	if rule := mgr.CheckSavedApprovalRules(SenderInfo{UnitName: "gh"}, savedRuleTestRequest(map[string]string{"service": "ghp"}).Items, RequestTypeGetSecret, nil); rule != nil {
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

	autoApproved, err := mgr.RequireApproval(context.Background(), "client", savedRuleTestRequest(map[string]string{"service": "github"}).Items, "", RequestTypeGetSecret, nil, SenderInfo{UnitName: "gh"})
	if !errors.Is(err, ErrDeniedByRule) {
		t.Fatalf("RequireApproval error = %v, want ErrDeniedByRule", err)
	}
	if !autoApproved {
		t.Fatal("rule-denied request should be resolved without prompting")
	}
}
