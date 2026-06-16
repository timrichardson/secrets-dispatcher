package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidRule is returned when a saved approval rule is malformed.
var ErrInvalidRule = errors.New("invalid approval rule")

// SavedApprovalRule is a user-managed durable approve rule stored in the state directory.
type SavedApprovalRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	RequestTypes     []string          `json:"request_types"`
	Process          *ProcessMatcher   `json:"process,omitempty"`
	Secret           *SecretMatcher    `json:"secret,omitempty"`
	SearchAttributes map[string]string `json:"search_attributes,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// SavedApprovalRuleStore persists user-managed approval rules.
type SavedApprovalRuleStore interface {
	Load() ([]SavedApprovalRule, error)
	Save([]SavedApprovalRule) error
}

// FileSavedApprovalRuleStore stores approval rules as JSON under the state directory.
type FileSavedApprovalRuleStore struct {
	path string
}

type savedApprovalRuleFile struct {
	Version int                 `json:"version"`
	Rules   []SavedApprovalRule `json:"rules"`
}

// NewFileSavedApprovalRuleStore creates a JSON store in stateDir.
func NewFileSavedApprovalRuleStore(stateDir string) *FileSavedApprovalRuleStore {
	return &FileSavedApprovalRuleStore{path: filepath.Join(stateDir, "approval-rules.json")}
}

// Load reads saved approval rules. A missing file means no saved rules.
func (s *FileSavedApprovalRuleStore) Load() ([]SavedApprovalRule, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var file savedApprovalRuleFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported saved approval rules version %d", file.Version)
	}
	for i := range file.Rules {
		if err := ValidateSavedApprovalRule(&file.Rules[i]); err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return cloneSavedApprovalRules(file.Rules), nil
}

// Save atomically writes saved approval rules with private file permissions.
func (s *FileSavedApprovalRuleStore) Save(rules []SavedApprovalRule) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(savedApprovalRuleFile{
		Version: 1,
		Rules:   rules,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".approval-rules-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// ValidateSavedApprovalRule checks saved-rule syntax and prevents global allow rules.
func ValidateSavedApprovalRule(rule *SavedApprovalRule) error {
	if rule == nil {
		return fmt.Errorf("%w: missing rule", ErrInvalidRule)
	}
	if rule.ID == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidRule)
	}
	if len(rule.RequestTypes) == 0 {
		return fmt.Errorf("%w: request_types must not be empty", ErrInvalidRule)
	}
	for _, rt := range rule.RequestTypes {
		if !validRequestType(rt) {
			return fmt.Errorf("%w: invalid request_type %q", ErrInvalidRule, rt)
		}
	}
	if !hasProcessMatcher(rule.Process) {
		return fmt.Errorf("%w: process matcher is required", ErrInvalidRule)
	}

	for _, pat := range []struct{ name, value string }{
		{"process.exe", strFromProcess(rule.Process, "exe")},
		{"process.name", strFromProcess(rule.Process, "name")},
		{"process.cwd", strFromProcess(rule.Process, "cwd")},
		{"process.unit", strFromProcess(rule.Process, "unit")},
		{"secret.collection", strFromSecret(rule.Secret, "collection")},
		{"secret.label", strFromSecret(rule.Secret, "label")},
	} {
		if pat.value == "" {
			continue
		}
		if _, err := path.Match(pat.value, "test"); err != nil {
			return fmt.Errorf("%w: invalid glob in %s: %v", ErrInvalidRule, pat.name, err)
		}
	}
	if rule.Secret != nil {
		for k, v := range rule.Secret.Attributes {
			if _, err := path.Match(v, "test"); err != nil {
				return fmt.Errorf("%w: invalid glob in secret.attributes[%s]: %v", ErrInvalidRule, k, err)
			}
		}
	}
	for k, v := range rule.SearchAttributes {
		if _, err := path.Match(v, "test"); err != nil {
			return fmt.Errorf("%w: invalid glob in search_attributes[%s]: %v", ErrInvalidRule, k, err)
		}
	}
	return nil
}

func validRequestType(rt string) bool {
	switch RequestType(rt) {
	case RequestTypeGetSecret, RequestTypeSearch, RequestTypeDelete, RequestTypeWrite,
		RequestTypeSSHSign, RequestTypeUnlock, RequestTypeGPGSign:
		return true
	default:
		return false
	}
}

func hasProcessMatcher(pm *ProcessMatcher) bool {
	return pm != nil && (pm.Exe != "" || pm.Name != "" || pm.CWD != "" || pm.Unit != "")
}

func strFromProcess(p *ProcessMatcher, field string) string {
	if p == nil {
		return ""
	}
	switch field {
	case "exe":
		return p.Exe
	case "name":
		return p.Name
	case "cwd":
		return p.CWD
	case "unit":
		return p.Unit
	default:
		return ""
	}
}

func strFromSecret(s *SecretMatcher, field string) string {
	if s == nil {
		return ""
	}
	switch field {
	case "collection":
		return s.Collection
	case "label":
		return s.Label
	default:
		return ""
	}
}

// ListSavedApprovalRules returns user-managed saved approval rules.
func (m *Manager) ListSavedApprovalRules() []SavedApprovalRule {
	m.savedRulesMu.Lock()
	defer m.savedRulesMu.Unlock()
	return cloneSavedApprovalRules(m.savedRules)
}

// CreateSavedApprovalRule stores a new saved approval rule.
func (m *Manager) CreateSavedApprovalRule(rule SavedApprovalRule) (SavedApprovalRule, error) {
	now := time.Now()
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	if rule.Name == "" {
		rule.Name = defaultSavedRuleName(&rule)
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	if !rule.Enabled {
		rule.Enabled = true
	}
	rule = cloneSavedApprovalRule(rule)
	if err := ValidateSavedApprovalRule(&rule); err != nil {
		return SavedApprovalRule{}, err
	}

	m.savedRulesMu.Lock()
	updated := cloneSavedApprovalRules(m.savedRules)
	updated = append(updated, rule)
	if err := m.saveSavedRulesLocked(updated); err != nil {
		m.savedRulesMu.Unlock()
		return SavedApprovalRule{}, err
	}
	m.savedRules = updated
	m.savedRulesMu.Unlock()

	m.notify(Event{Type: EventSavedApprovalRuleAdded, SavedRule: &rule})
	slog.Info("saved approval rule added", "rule_id", rule.ID, "rule_name", rule.Name)
	return rule, nil
}

// UpdateSavedApprovalRule replaces a saved approval rule while preserving creation metadata.
func (m *Manager) UpdateSavedApprovalRule(id string, rule SavedApprovalRule) (SavedApprovalRule, error) {
	if id == "" {
		return SavedApprovalRule{}, ErrNotFound
	}

	m.savedRulesMu.Lock()
	idx := -1
	updated := cloneSavedApprovalRules(m.savedRules)
	for i := range updated {
		if updated[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		m.savedRulesMu.Unlock()
		return SavedApprovalRule{}, ErrNotFound
	}

	rule.ID = id
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = updated[idx].CreatedAt
	}
	rule.UpdatedAt = time.Now()
	if rule.Name == "" {
		rule.Name = defaultSavedRuleName(&rule)
	}
	rule = cloneSavedApprovalRule(rule)
	if err := ValidateSavedApprovalRule(&rule); err != nil {
		m.savedRulesMu.Unlock()
		return SavedApprovalRule{}, err
	}
	updated[idx] = rule
	if err := m.saveSavedRulesLocked(updated); err != nil {
		m.savedRulesMu.Unlock()
		return SavedApprovalRule{}, err
	}
	m.savedRules = updated
	m.savedRulesMu.Unlock()

	m.notify(Event{Type: EventSavedApprovalRuleUpdated, SavedRule: &rule})
	slog.Info("saved approval rule updated", "rule_id", rule.ID, "rule_name", rule.Name)
	return rule, nil
}

// RemoveSavedApprovalRule deletes a saved approval rule.
func (m *Manager) RemoveSavedApprovalRule(id string) error {
	m.savedRulesMu.Lock()
	idx := -1
	updated := cloneSavedApprovalRules(m.savedRules)
	var removed SavedApprovalRule
	for i, rule := range updated {
		if rule.ID == id {
			idx = i
			removed = rule
			break
		}
	}
	if idx < 0 {
		m.savedRulesMu.Unlock()
		return ErrNotFound
	}
	updated = append(updated[:idx], updated[idx+1:]...)
	if err := m.saveSavedRulesLocked(updated); err != nil {
		m.savedRulesMu.Unlock()
		return err
	}
	m.savedRules = updated
	m.savedRulesMu.Unlock()

	m.notify(Event{Type: EventSavedApprovalRuleRemoved, SavedRule: &removed})
	slog.Info("saved approval rule removed", "rule_id", id)
	return nil
}

// CreateSavedApprovalRuleFromRequest creates a saved rule from a pending or eligible history request.
func (m *Manager) CreateSavedApprovalRuleFromRequest(requestID string) (SavedApprovalRule, error) {
	if req := m.GetPending(requestID); req != nil {
		return m.CreateSavedApprovalRule(savedApprovalRuleFromRequest(req))
	}
	entry := m.GetHistoryEntry(requestID)
	if entry == nil {
		return SavedApprovalRule{}, ErrNotFound
	}
	if entry.Resolution != ResolutionApproved &&
		entry.Resolution != ResolutionCancelled &&
		entry.Resolution != ResolutionAutoApproved {
		return SavedApprovalRule{}, ErrNotFound
	}
	return m.CreateSavedApprovalRule(savedApprovalRuleFromRequest(entry.Request))
}

// PersistAutoApproveRule creates a saved rule from a temporary rule and removes the temporary rule.
func (m *Manager) PersistAutoApproveRule(id string) (SavedApprovalRule, error) {
	m.autoApproveMu.Lock()
	var tmp AutoApproveRule
	found := false
	for _, rule := range m.autoApproveRules {
		if rule.ID == id && rule.ExpiresAt.After(time.Now()) {
			tmp = rule
			found = true
			break
		}
	}
	m.autoApproveMu.Unlock()
	if !found {
		return SavedApprovalRule{}, ErrNotFound
	}

	saved, err := m.CreateSavedApprovalRule(savedApprovalRuleFromTemporary(tmp))
	if err != nil {
		return SavedApprovalRule{}, err
	}
	if err := m.RemoveAutoApproveRule(id); err != nil && !errors.Is(err, ErrNotFound) {
		return SavedApprovalRule{}, err
	}
	return saved, nil
}

// CheckSavedApprovalRules exposes saved rule matching for flows outside RequireApproval.
func (m *Manager) CheckSavedApprovalRules(senderInfo SenderInfo, items []ItemInfo, reqType RequestType, searchAttrs map[string]string) *SavedApprovalRule {
	return m.checkSavedApprovalRules(senderInfo, items, reqType, searchAttrs)
}

func (m *Manager) checkSavedApprovalRules(senderInfo SenderInfo, items []ItemInfo, reqType RequestType, searchAttrs map[string]string) *SavedApprovalRule {
	m.savedRulesMu.Lock()
	defer m.savedRulesMu.Unlock()
	for i := range m.savedRules {
		rule := &m.savedRules[i]
		if !rule.Enabled {
			continue
		}
		if matchSavedApprovalRule(rule, senderInfo, items, reqType, searchAttrs) {
			matched := cloneSavedApprovalRule(*rule)
			return &matched
		}
	}
	return nil
}

func matchSavedApprovalRule(rule *SavedApprovalRule, senderInfo SenderInfo, items []ItemInfo, reqType RequestType, searchAttrs map[string]string) bool {
	trust := TrustRule{
		RequestTypes:     rule.RequestTypes,
		Process:          rule.Process,
		Secret:           rule.Secret,
		SearchAttributes: rule.SearchAttributes,
	}
	return matchTrustRule(&trust, senderInfo, items, reqType, searchAttrs)
}

func (m *Manager) saveSavedRulesLocked(rules []SavedApprovalRule) error {
	if m.savedRulesStore == nil {
		return nil
	}
	return m.savedRulesStore.Save(rules)
}

func savedApprovalRuleFromRequest(req *Request) SavedApprovalRule {
	rule := SavedApprovalRule{
		Enabled:      true,
		RequestTypes: []string{string(req.Type)},
		Process:      processMatcherFromSender(req.SenderInfo),
	}
	if req.Type == RequestTypeSearch {
		rule.SearchAttributes = quoteMap(req.SearchAttributes)
	} else if len(req.Items) > 0 {
		item := req.Items[0]
		rule.Secret = &SecretMatcher{
			Collection: globQuote(extractCollection(item.Path)),
			Attributes: quoteMap(item.Attributes),
		}
	}
	rule.Name = defaultSavedRuleName(&rule)
	return rule
}

func savedApprovalRuleFromTemporary(rule AutoApproveRule) SavedApprovalRule {
	saved := SavedApprovalRule{
		Enabled:      true,
		RequestTypes: []string{string(rule.RequestType)},
		Process:      &ProcessMatcher{Unit: globQuote(rule.InvokerName)},
	}
	if rule.RequestType == RequestTypeSearch {
		saved.SearchAttributes = quoteMap(rule.Attributes)
	} else {
		saved.Secret = &SecretMatcher{
			Collection: globQuote(rule.Collection),
			Attributes: quoteMap(rule.Attributes),
		}
	}
	saved.Name = defaultSavedRuleName(&saved)
	return saved
}

func processMatcherFromSender(sender SenderInfo) *ProcessMatcher {
	if sender.UnitName != "" {
		return &ProcessMatcher{Unit: globQuote(sender.UnitName)}
	}
	if len(sender.ProcessChain) > 0 {
		first := sender.ProcessChain[0]
		if first.Exe != "" {
			return &ProcessMatcher{Exe: globQuote(first.Exe)}
		}
		if first.Name != "" {
			return &ProcessMatcher{Name: globQuote(first.Name)}
		}
	}
	return nil
}

func defaultSavedRuleName(rule *SavedApprovalRule) string {
	process := "process"
	if rule.Process != nil {
		switch {
		case rule.Process.Unit != "":
			process = rule.Process.Unit
		case rule.Process.Name != "":
			process = rule.Process.Name
		case rule.Process.Exe != "":
			process = filepath.Base(rule.Process.Exe)
		}
	}
	reqType := "requests"
	if len(rule.RequestTypes) > 0 {
		reqType = strings.Join(rule.RequestTypes, ", ")
	}
	return fmt.Sprintf("%s %s", process, reqType)
}

func quoteMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = globQuote(v)
	}
	return out
}

func globQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '?', '[':
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func cloneSavedApprovalRules(in []SavedApprovalRule) []SavedApprovalRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]SavedApprovalRule, len(in))
	for i := range in {
		out[i] = cloneSavedApprovalRule(in[i])
	}
	return out
}

func cloneSavedApprovalRule(in SavedApprovalRule) SavedApprovalRule {
	in.RequestTypes = slices.Clone(in.RequestTypes)
	in.SearchAttributes = cloneStringMap(in.SearchAttributes)
	if in.Process != nil {
		proc := *in.Process
		in.Process = &proc
	}
	if in.Secret != nil {
		secret := *in.Secret
		secret.Attributes = cloneStringMap(in.Secret.Attributes)
		in.Secret = &secret
	}
	return in
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
