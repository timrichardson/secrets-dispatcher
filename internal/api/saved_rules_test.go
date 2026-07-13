package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nikicat/secrets-dispatcher/internal/approval"
)

func TestHandlers_SavedApprovalRulesCRUD(t *testing.T) {
	mgr := approval.NewManager(approval.ManagerConfig{Timeout: time.Minute, HistoryMax: 10})
	h := NewHandlers(mgr, "/tmp/socket", "client", nil, false, nil, time.Second)

	createBody := []byte(`{
    "name":"gh github",
    "enabled":true,
    "request_types":["get_secret"],
    "process":{"unit":"gh"},
    "secret":{"collection":"login","attributes":{"service":"github"}}
  }`)
	rec := httptest.NewRecorder()
	h.HandleSavedApprovalRuleCreate(rec, httptest.NewRequest(http.MethodPost, "/api/v1/approval-rules", bytes.NewReader(createBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	var created approval.SavedApprovalRule
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created rule ID is empty")
	}

	created.Enabled = false
	rec = httptest.NewRecorder()
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(created); err != nil {
		t.Fatalf("encode update: %v", err)
	}
	h.HandleSavedApprovalRuleUpdate(rec, httptest.NewRequest(http.MethodPut, "/api/v1/approval-rules/"+created.ID, buf))
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updated approval.SavedApprovalRule
	if err := json.NewDecoder(rec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Enabled {
		t.Fatal("expected updated rule to be disabled")
	}

	rec = httptest.NewRecorder()
	h.HandleSavedApprovalRuleDelete(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/approval-rules/"+created.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := mgr.ListSavedApprovalRules(); len(got) != 0 {
		t.Fatalf("saved rules after delete = %d, want 0", len(got))
	}
}

func TestHandlers_PersistAutoApproveRule(t *testing.T) {
	mgr := approval.NewManager(approval.ManagerConfig{Timeout: time.Minute, HistoryMax: 10, AutoApproveDuration: time.Minute})
	h := NewHandlers(mgr, "/tmp/socket", "client", nil, false, nil, time.Second)
	tempID := mgr.AddAutoApproveRule(&approval.Request{
		Type: approval.RequestTypeGetSecret,
		Items: []approval.ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Attributes: map[string]string{"service": "github"},
		}},
		SenderInfo: approval.SenderInfo{
			InvokerName:  "gh",
			ProcessChain: []approval.ProcessInfo{{Name: "gh", PID: 1, Exe: "/usr/bin/gh"}},
		},
	})

	rec := httptest.NewRecorder()
	h.HandleAutoApprovePersist(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auto-approve/"+tempID+"/persist", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("persist status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := mgr.ListSavedApprovalRules(); len(got) != 1 {
		t.Fatalf("saved rules = %d, want 1", len(got))
	}
	if got := mgr.ListAutoApproveRules(); len(got) != 0 {
		t.Fatalf("temporary rules = %d, want 0", len(got))
	}
}
