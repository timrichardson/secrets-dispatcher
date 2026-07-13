// Package notification provides desktop notifications for approval requests.
package notification

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/nikicat/secrets-dispatcher/internal/approval"
)

const (
	notifyDest      = "org.freedesktop.Notifications"
	notifyPath      = "/org/freedesktop/Notifications"
	notifyInterface = "org.freedesktop.Notifications"
)

// Notifier defines the interface for sending desktop notifications.
type Notifier interface {
	// Notify sends a notification and returns its ID.
	// The actions parameter takes alternating (id, label) pairs per the FreeDesktop spec.
	Notify(summary, body, icon string, actions []string) (uint32, error)
	// NotifyReplacing updates an existing notification in place.
	NotifyReplacing(replacesID uint32, summary, body, icon string, actions []string) (uint32, error)
	// Close closes a notification by ID.
	Close(id uint32) error
}

// Approver resolves approval requests.
type Approver interface {
	Approve(id string) error
	Deny(id string) error
	ApproveForProcess(id string) error
	ApproveFor24Hours(id string) error
	CreateSavedRuleFromRequest(requestID string) error
}

// Action represents a user interaction with a notification button.
type Action struct {
	NotificationID uint32
	ActionKey      string // "approve" or "deny"
}

// DBusNotifier sends notifications via D-Bus and listens for action button clicks.
// It automatically reconnects if the session bus connection drops.
type DBusNotifier struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	signals chan *dbus.Signal
	actions chan Action
	done    chan struct{}
}

// NewDBusNotifier creates a notifier using a private session bus connection and
// starts listening for ActionInvoked signals.
func NewDBusNotifier() (*DBusNotifier, error) {
	n := &DBusNotifier{
		signals: make(chan *dbus.Signal, 16),
		actions: make(chan Action, 16),
		done:    make(chan struct{}),
	}

	if err := n.connect(); err != nil {
		return nil, err
	}

	go n.processSignals(n.signals)

	return n, nil
}

// connect establishes a private session bus connection and subscribes to
// ActionInvoked signals. Must be called with n.mu held (or during construction).
func (n *DBusNotifier) connect() error {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("connect to session bus: %w", err)
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface(notifyInterface),
		dbus.WithMatchMember("ActionInvoked"),
	); err != nil {
		conn.Close()
		return fmt.Errorf("subscribe to ActionInvoked: %w", err)
	}

	conn.Signal(n.signals)
	n.conn = conn
	return nil
}

// reconnect closes the dead connection and establishes a new one.
// It creates a fresh signals channel and restarts the processSignals goroutine
// (the old one exits when godbus closes its channel via Terminate).
// Must be called with n.mu held.
func (n *DBusNotifier) reconnect() error {
	if n.conn != nil {
		n.conn.Close()
	}
	n.signals = make(chan *dbus.Signal, 16)
	if err := n.connect(); err != nil {
		return fmt.Errorf("reconnect: %w", err)
	}
	go n.processSignals(n.signals)
	slog.Info("reconnected to D-Bus session bus")
	return nil
}

// Actions returns a channel that receives action button clicks.
func (n *DBusNotifier) Actions() <-chan Action {
	return n.actions
}

// Stop stops the signal listener goroutine and closes the D-Bus connection.
func (n *DBusNotifier) Stop() {
	close(n.done)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn != nil {
		n.conn.Close()
	}
}

func (n *DBusNotifier) processSignals(ch <-chan *dbus.Signal) {
	for {
		select {
		case <-n.done:
			return
		case sig, ok := <-ch:
			if !ok {
				return // channel closed (connection died)
			}
			if sig.Name != notifyInterface+".ActionInvoked" {
				continue
			}
			if len(sig.Body) != 2 {
				continue
			}
			id, ok1 := sig.Body[0].(uint32)
			key, ok2 := sig.Body[1].(string)
			if !ok1 || !ok2 {
				continue
			}
			select {
			case n.actions <- Action{NotificationID: id, ActionKey: key}:
			case <-n.done:
				return
			}
		}
	}
}

// Notify sends a desktop notification with optional action buttons.
// If the D-Bus connection is dead, it reconnects and retries once.
func (n *DBusNotifier) Notify(summary, body, icon string, actions []string) (uint32, error) {
	return n.notifyReplacing(0, summary, body, icon, actions)
}

// NotifyReplacing updates an existing notification without creating another banner.
func (n *DBusNotifier) NotifyReplacing(replacesID uint32, summary, body, icon string, actions []string) (uint32, error) {
	return n.notifyReplacing(replacesID, summary, body, icon, actions)
}

func (n *DBusNotifier) notifyReplacing(replacesID uint32, summary, body, icon string, actions []string) (uint32, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Approval notifications are actionable security prompts. Ask the notification
	// server not to auto-expire them; otherwise GNOME may hide the Approve/Deny
	// buttons before the request timeout has elapsed.
	id, err := n.doNotify(summary, body, icon, actions, 2, replacesID) // urgency: critical
	if err != nil && errors.Is(err, dbus.ErrClosed) {
		if reconnErr := n.reconnect(); reconnErr != nil {
			return 0, fmt.Errorf("notify call: %w (reconnect failed: %v)", err, reconnErr)
		}
		id, err = n.doNotify(summary, body, icon, actions, 2, replacesID)
	}
	return id, err
}

func (n *DBusNotifier) doNotify(summary, body, icon string, actions []string, urgency byte, replacesID uint32) (uint32, error) {
	return n.doNotifyFull(summary, body, icon, actions, urgency, 0, replacesID)
}

func (n *DBusNotifier) doNotifyFull(summary, body, icon string, actions []string, urgency byte, expireTimeout int32, replacesID uint32) (uint32, error) {
	obj := n.conn.Object(notifyDest, notifyPath)
	call := obj.Call(
		notifyInterface+".Notify",
		0,
		"secrets-dispatcher", // app_name
		replacesID,           // replaces_id (0 = new notification)
		icon,                 // app_icon
		summary,              // summary
		body,                 // body
		actions,              // actions (alternating id, label pairs)
		map[string]dbus.Variant{
			"urgency": dbus.MakeVariant(urgency),
		},
		expireTimeout,
	)
	if call.Err != nil {
		return 0, fmt.Errorf("notify call: %w", call.Err)
	}

	var id uint32
	if err := call.Store(&id); err != nil {
		return 0, fmt.Errorf("store notify result: %w", err)
	}
	return id, nil
}

// NotifyPersistent sends a critical notification that never auto-expires.
// Dismiss it with Close (CloseNotification).
func (n *DBusNotifier) NotifyPersistent(summary, body, icon string) (uint32, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	id, err := n.doNotifyFull(summary, body, icon, nil, 2, 0, 0) // critical, never expire
	if err != nil && errors.Is(err, dbus.ErrClosed) {
		if reconnErr := n.reconnect(); reconnErr != nil {
			return 0, fmt.Errorf("notify call: %w (reconnect failed: %v)", err, reconnErr)
		}
		id, err = n.doNotifyFull(summary, body, icon, nil, 2, 0, 0)
	}
	return id, err
}

// Close closes a notification by ID.
// If the D-Bus connection is dead, it reconnects and retries once.
func (n *DBusNotifier) Close(id uint32) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	err := n.doClose(id)
	if err != nil && errors.Is(err, dbus.ErrClosed) {
		if reconnErr := n.reconnect(); reconnErr != nil {
			return fmt.Errorf("close notification: %w (reconnect failed: %v)", err, reconnErr)
		}
		err = n.doClose(id)
	}
	return err
}

func (n *DBusNotifier) doClose(id uint32) error {
	obj := n.conn.Object(notifyDest, notifyPath)
	call := obj.Call(notifyInterface+".CloseNotification", 0, id)
	if call.Err != nil {
		return fmt.Errorf("close notification: %w", call.Err)
	}
	return nil
}

// delayGroup schedules callbacks by key with a grace period.
// If Cancel is called before the timer fires, the callback is suppressed.
type delayGroup struct {
	mu     sync.Mutex
	timers map[string]*time.Timer
}

func newDelayGroup() *delayGroup {
	return &delayGroup{timers: make(map[string]*time.Timer)}
}

// Schedule registers a callback to fire after delay. If a timer already exists
// for the key it is replaced. The callback is only invoked if the timer is
// still pending (not cancelled) when it fires.
func (g *delayGroup) Schedule(key string, delay time.Duration, fn func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if old, ok := g.timers[key]; ok {
		old.Stop()
	}
	g.timers[key] = time.AfterFunc(delay, func() {
		g.mu.Lock()
		_, stillPending := g.timers[key]
		if stillPending {
			delete(g.timers, key)
		}
		g.mu.Unlock()
		if stillPending {
			fn()
		}
	})
}

// Cancel stops a pending timer and returns true if one was pending.
func (g *delayGroup) Cancel(key string) bool {
	g.mu.Lock()
	timer, ok := g.timers[key]
	if ok {
		delete(g.timers, key)
	}
	g.mu.Unlock()
	if ok {
		timer.Stop()
	}
	return ok
}

type notificationGroup struct {
	key            string
	notificationID uint32
	requestIDs     []string
	request        *approval.Request
}

// Handler receives approval events and shows desktop notifications.
// It also processes notification action button clicks (Approve/Deny).
type Handler struct {
	notifier            Notifier
	approver            Approver
	baseURL             string
	showPIDs            bool
	autoApproveDuration time.Duration
	notificationDelay   time.Duration
	openURL             func(string) // injectable for testing; defaults to xdg-open

	mu            sync.Mutex
	notifications map[string]uint32 // request ID -> notification ID
	requests      map[uint32]string // notification ID -> representative request ID
	groups        map[string]*notificationGroup
	requestGroups map[string]string // request ID -> group key
	rulePrompts   map[uint32]string // follow-up notification ID -> source request ID
	pending       *delayGroup       // notifications waiting for the grace period

}

// NewHandler creates a notification handler.
// baseURL is the web UI URL opened when the user clicks the notification body.
// autoApproveDuration controls the explanatory text for the "Approve similar"
// button.
// notificationDelay is the grace period before showing a desktop notification;
// requests cancelled within this window produce no notification at all.
func NewHandler(notifier Notifier, approver Approver, baseURL string, showPIDs bool, autoApproveDuration, notificationDelay time.Duration) *Handler {
	return &Handler{
		notifier:            notifier,
		approver:            approver,
		baseURL:             baseURL,
		showPIDs:            showPIDs,
		autoApproveDuration: autoApproveDuration,
		notificationDelay:   notificationDelay,
		openURL:             func(u string) { exec.Command("xdg-open", u).Start() },
		notifications:       make(map[string]uint32),
		requests:            make(map[uint32]string),
		groups:              make(map[string]*notificationGroup),
		requestGroups:       make(map[string]string),
		rulePrompts:         make(map[uint32]string),
		pending:             newDelayGroup(),
	}
}

func approvalActions() []string {
	return []string{
		"approve", "Approve once",
		"deny", "Deny",
		"details", "Details",
	}
}

func detailsHint() string {
	return " • Select Details for full request information"
}

// ListenActions reads from the actions channel and resolves requests.
// It blocks until the channel is closed or ctx is cancelled.
func (h *Handler) ListenActions(ctx context.Context, actions <-chan Action) {
	for {
		select {
		case <-ctx.Done():
			return
		case action, ok := <-actions:
			if !ok {
				return
			}
			h.handleAction(action)
		}
	}
}

func (h *Handler) handleDetails(notificationID uint32) {
	h.mu.Lock()
	reqID, ok := h.requests[notificationID]
	key := h.requestGroups[reqID]
	group := h.groups[key]
	if !ok || group == nil {
		h.mu.Unlock()
		return
	}
	req := group.request
	count := len(group.requestIDs)
	h.mu.Unlock()

	h.openURL(h.baseURL + "?request=" + reqID)

	// GNOME dismisses a notification after every action, including Details.
	// Reissue it after the action has finished so the pending approval remains
	// visible and actionable.
	time.AfterFunc(150*time.Millisecond, func() {
		body := h.formatBody(req)
		if count > 1 {
			body += fmt.Sprintf(" • <b>Repeated:</b> %d equivalent requests", count)
		}
		body += detailsHint()
		summary, icon := h.notificationMeta(req)
		newID, err := h.notifier.Notify(summary, body, icon, approvalActions())
		if err != nil {
			slog.Error("failed to reissue notification after opening details", "error", err, "request_id", reqID)
			return
		}

		h.mu.Lock()
		current := h.groups[key]
		if current == nil || current.notificationID != notificationID {
			h.mu.Unlock()
			_ = h.notifier.Close(newID)
			return
		}
		delete(h.requests, notificationID)
		current.notificationID = newID
		for _, id := range current.requestIDs {
			h.notifications[id] = newID
		}
		h.requests[newID] = current.requestIDs[0]
		h.mu.Unlock()
	})
}

func (h *Handler) handleAction(action Action) {
	if action.ActionKey == "details" {
		h.handleDetails(action.NotificationID)
		return
	}
	if action.ActionKey == "default" {
		h.mu.Lock()
		_, requestOK := h.requests[action.NotificationID]
		_, rulePrompt := h.rulePrompts[action.NotificationID]
		h.mu.Unlock()
		if requestOK {
			h.handleDetails(action.NotificationID)
		} else if rulePrompt {
			h.openURL(h.baseURL + "?view=rules")
		}
		return
	}

	h.mu.Lock()
	reqID, ok := h.requests[action.NotificationID]
	requestIDs := []string{reqID}
	if ok {
		if key, found := h.requestGroups[reqID]; found {
			if group := h.groups[key]; group != nil {
				requestIDs = append([]string(nil), group.requestIDs...)
				delete(h.groups, key)
			}
		}
		// Remove maps now so synchronous resolution callbacks do not close or
		// re-resolve the grouped notification.
		delete(h.requests, action.NotificationID)
		for _, id := range requestIDs {
			delete(h.notifications, id)
			delete(h.requestGroups, id)
		}
	}
	ruleReqID, rulePrompt := h.rulePrompts[action.NotificationID]
	if rulePrompt {
		delete(h.rulePrompts, action.NotificationID)
	}
	h.mu.Unlock()

	if rulePrompt {
		h.handleRulePromptAction(action.ActionKey, ruleReqID)
		return
	}

	if !ok {
		return
	}

	if action.ActionKey == "dismiss" {
		return
	}

	for _, id := range requestIDs {
		var err error
		switch action.ActionKey {
		case "approve":
			err = h.approver.Approve(id)
		case "allow_process":
			err = h.approver.ApproveForProcess(id)
		case "allow_24h":
			err = h.approver.ApproveFor24Hours(id)
		case "deny":
			err = h.approver.Deny(id)
		default:
			slog.Debug("unknown action key", "action", action.ActionKey, "request_id", id)
			return
		}
		if err != nil {
			if errors.Is(err, approval.ErrNotFound) {
				slog.Debug("request already resolved", "action", action.ActionKey, "request_id", id)
			} else {
				slog.Error("failed to resolve request from notification", "action", action.ActionKey, "request_id", id, "error", err)
			}
			continue
		}
		slog.Info("resolved request from notification", "action", action.ActionKey, "request_id", id)
	}
}

func (h *Handler) handleRulePromptAction(actionKey, requestID string) {
	switch actionKey {
	case "save_rule":
		if err := h.approver.CreateSavedRuleFromRequest(requestID); err != nil {
			if errors.Is(err, approval.ErrNotFound) {
				slog.Debug("request unavailable for saved rule", "request_id", requestID)
			} else {
				slog.Error("failed to save approval rule", "request_id", requestID, "error", err)
			}
			return
		}
		slog.Info("saved approval rule from notification", "request_id", requestID)
	case "review_rules", "default":
		h.openURL(h.baseURL + "?view=rules")
	case "dismiss":
		return
	default:
		slog.Debug("unknown rule prompt action key", "action", actionKey, "request_id", requestID)
	}
}

// OnEvent implements approval.Observer.
func (h *Handler) OnEvent(event approval.Event) {
	switch event.Type {
	case approval.EventRequestCreated:
		h.handleCreated(event.Request)
	case approval.EventRequestCancelled:
		h.handleCancelled(event.Request)
	case approval.EventRequestApproved, approval.EventRequestDenied,
		approval.EventRequestExpired, approval.EventRequestAutoApproved:
		h.handleResolved(event.Request.ID)
	}
}

// notificationMeta returns the summary title and icon for a request based on its type.
func (h *Handler) notificationMeta(req *approval.Request) (summary, icon string) {
	switch req.Type {
	case approval.RequestTypeGPGSign:
		return "Sign commit", "emblem-important"
	case approval.RequestTypeSearch:
		return "Secrets searched", "dialog-password"
	case approval.RequestTypeDelete:
		return "Deletion requested", "dialog-warning"
	case approval.RequestTypeWrite:
		return "Secret write requested", "dialog-warning"
	case approval.RequestTypeSSHSign:
		return "SSH key requested", "dialog-password"
	default:
		return "Secret requested", "dialog-password"
	}
}

func (h *Handler) handleCreated(req *approval.Request) {
	if h.notificationDelay <= 0 {
		h.sendNotification(req)
		return
	}
	h.pending.Schedule(req.ID, h.notificationDelay, func() {
		h.sendNotification(req)
	})
}

func requestGroupKey(req *approval.Request) string {
	var parts []string
	app := req.SenderInfo.InvokerName
	if len(req.SenderInfo.ProcessChain) > 0 {
		p := req.SenderInfo.ProcessChain[0]
		app = p.Exe
		if app == "" {
			app = p.Name
		}
	}
	parts = append(parts, app, string(req.Type))
	for _, item := range req.Items {
		parts = append(parts, item.Path, item.Label)
		keys := make([]string, 0, len(item.Attributes))
		for k := range item.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"="+item.Attributes[k])
		}
	}
	keys := make([]string, 0, len(req.SearchAttributes))
	for k := range req.SearchAttributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+req.SearchAttributes[k])
	}
	return strings.Join(parts, "\x00")
}

func notificationApplication(req *approval.Request) string {
	if len(req.SenderInfo.ProcessChain) > 0 && req.SenderInfo.ProcessChain[0].Name != "" {
		return req.SenderInfo.ProcessChain[0].Name
	}
	if req.SenderInfo.InvokerName != "" {
		return strings.TrimSuffix(req.SenderInfo.InvokerName, ".service")
	}
	if req.Client != "" {
		return req.Client
	}
	return "Unknown application"
}

func requestActionLabel(t approval.RequestType) string {
	switch t {
	case approval.RequestTypeSearch:
		return "Search secrets"
	case approval.RequestTypeDelete:
		return "Delete secret"
	case approval.RequestTypeWrite:
		return "Write secret"
	case approval.RequestTypeSSHSign:
		return "Use SSH key"
	case approval.RequestTypeUnlock:
		return "Unlock collection"
	default:
		return "Read secret"
	}
}

func requestSecretLabel(req *approval.Request) string {
	if len(req.Items) == 1 {
		item := req.Items[0]
		if item.Label != "" && !strings.HasPrefix(item.Label, "org.freedesktop.Secret.") {
			return item.Label
		}
		attrs := item.Attributes
		service := firstAttribute(attrs, "service", "application", "app", "xdg:schema")
		account := firstAttribute(attrs, "account", "username", "user")
		purpose := ""
		if strings.HasSuffix(account, "_accessTokenKey") {
			account = strings.TrimSuffix(account, "_accessTokenKey")
			purpose = "access token"
		}
		if len(account) > 8 {
			account = account[:8] + "…"
		}
		var description string
		switch {
		case service != "" && purpose != "":
			description = service + " — " + purpose
		case service != "":
			description = service
		case purpose != "":
			description = purpose
		default:
			description = "Generic secret"
		}
		if account != "" {
			description += " (account " + account + ")"
		}
		return description
	}
	if len(req.Items) > 1 {
		return fmt.Sprintf("%d secrets", len(req.Items))
	}
	if len(req.SearchAttributes) > 0 {
		keys := make([]string, 0, len(req.SearchAttributes))
		for k := range req.SearchAttributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		attrs := make([]string, 0, len(keys))
		for _, k := range keys {
			attrs = append(attrs, k+"="+req.SearchAttributes[k])
		}
		return strings.Join(attrs, ", ")
	}
	return "Unspecified"
}

func firstAttribute(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func (h *Handler) sendNotification(req *approval.Request) {
	summary, icon := h.notificationMeta(req)
	key := requestGroupKey(req)
	actions := approvalActions()

	h.mu.Lock()
	if group := h.groups[key]; group != nil {
		group.requestIDs = append(group.requestIDs, req.ID)
		h.notifications[req.ID] = group.notificationID
		h.requestGroups[req.ID] = key
		count := len(group.requestIDs)
		notificationID := group.notificationID
		body := h.formatBody(group.request)
		body += fmt.Sprintf(" • <b>Repeated:</b> %d equivalent requests", count)
		body += detailsHint()
		h.mu.Unlock()
		if _, err := h.notifier.NotifyReplacing(notificationID, summary, body, icon, actions); err != nil {
			slog.Error("failed to update grouped notification", "error", err, "request_id", req.ID)
		}
		return
	}
	h.mu.Unlock()

	body := h.formatBody(req)
	body += detailsHint()
	id, err := h.notifier.Notify(summary, body, icon, actions)
	if err != nil {
		slog.Error("failed to send notification", "error", err, "request_id", req.ID)
		return
	}

	h.mu.Lock()
	h.notifications[req.ID] = id
	h.requests[id] = req.ID
	h.requestGroups[req.ID] = key
	h.groups[key] = &notificationGroup{key: key, notificationID: id, requestIDs: []string{req.ID}, request: req}
	h.mu.Unlock()

	slog.Debug("sent desktop notification", "request_id", req.ID, "notification_id", id)
}

func (h *Handler) handleCancelled(req *approval.Request) {
	if h.pending.Cancel(req.ID) {
		slog.Debug("suppressed notification for quickly-cancelled request", "request_id", req.ID)
		return
	}
	h.removeRequestNotification(req.ID)
}

func (h *Handler) handleResolved(requestID string) {
	if h.pending.Cancel(requestID) {
		return
	}
	h.removeRequestNotification(requestID)
}

func (h *Handler) removeRequestNotification(requestID string) {
	h.mu.Lock()
	notifID, ok := h.notifications[requestID]
	if !ok {
		h.mu.Unlock()
		return
	}
	delete(h.notifications, requestID)
	key := h.requestGroups[requestID]
	delete(h.requestGroups, requestID)
	group := h.groups[key]
	if group != nil {
		for i, id := range group.requestIDs {
			if id == requestID {
				group.requestIDs = append(group.requestIDs[:i], group.requestIDs[i+1:]...)
				break
			}
		}
		if len(group.requestIDs) > 0 {
			h.requests[notifID] = group.requestIDs[0]
			remaining := len(group.requestIDs)
			req := group.request
			h.mu.Unlock()
			body := h.formatBody(req)
			if remaining > 1 {
				body += fmt.Sprintf(" • <b>Repeated:</b> %d equivalent requests", remaining)
			}
			body += detailsHint()
			summary, icon := h.notificationMeta(req)
			if _, err := h.notifier.NotifyReplacing(notifID, summary, body, icon, approvalActions()); err != nil {
				slog.Debug("failed to update grouped notification", "error", err, "notification_id", notifID)
			}
			return
		}
		delete(h.groups, key)
	}
	delete(h.requests, notifID)
	h.mu.Unlock()

	if err := h.notifier.Close(notifID); err != nil {
		slog.Debug("failed to close notification", "error", err, "notification_id", notifID)
		return
	}
	slog.Debug("closed desktop notification", "request_id", requestID, "notification_id", notifID)
}

// markupEscaper escapes the only characters that are special in the
// org.freedesktop.Notifications markup body: & < >. Quotes are deliberately
// left alone — body text never appears inside an attribute value, and
// html.EscapeString's &#39;/&#34; showed up literally on servers (dunst, mako,
// GNOME Shell) that don't decode numeric character references.
var markupEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func escapeMarkup(s string) string {
	return markupEscaper.Replace(s)
}

// commitSubject returns the first line of a commit message.
func commitSubject(msg string) string {
	if before, _, ok := strings.Cut(msg, "\n"); ok {
		return before
	}
	return msg
}

const maxNotificationProcesses = 2

// formatProcessChain keeps desktop notifications compact while retaining both
// the direct requester context and the root trust origin. Full ancestry remains
// available in the web UI opened by clicking the notification.
func (h *Handler) formatProcessChain(b *strings.Builder, chain []approval.ProcessInfo) {
	if len(chain) <= maxNotificationProcesses+1 {
		for i, p := range chain {
			if i > 0 {
				b.WriteString(" ← ")
			}
			b.WriteString(escapeMarkup(p.Name))
			if h.showPIDs {
				fmt.Fprintf(b, "[%d]", p.PID)
			}
		}
		return
	}

	for i, p := range chain[:maxNotificationProcesses] {
		if i > 0 {
			b.WriteString(" ← ")
		}
		b.WriteString(escapeMarkup(p.Name))
		if h.showPIDs {
			fmt.Fprintf(b, "[%d]", p.PID)
		}
	}
	fmt.Fprintf(b, " ← … (+%d) ← ", len(chain)-maxNotificationProcesses-1)
	root := chain[len(chain)-1]
	b.WriteString(escapeMarkup(root.Name))
	if h.showPIDs {
		fmt.Fprintf(b, "[%d]", root.PID)
	}
}

func (h *Handler) formatBody(req *approval.Request) string {
	var b strings.Builder

	// esc escapes client-controlled substrings before they are interpolated into
	// the org.freedesktop.Notifications markup body. Every dynamic value here
	// (repo/commit/label/search attrs, and process comm which is itself
	// attacker-settable via prctl) must be escaped; only our own literal <b>/<i>
	// tags are emitted raw. The notification carries approve/deny action buttons,
	// so unescaped markup could forge reassuring content on the consent surface.
	esc := escapeMarkup

	switch req.Type {
	case approval.RequestTypeGPGSign:
		if req.GPGSignInfo != nil {
			fmt.Fprintf(&b, "<b>%s</b>: <i>%s</i>", esc(req.GPGSignInfo.RepoName), esc(commitSubject(req.GPGSignInfo.CommitMsg)))
			if len(req.SenderInfo.ProcessChain) > 0 {
				b.WriteString(" • <b>Process:</b> ")
				h.formatProcessChain(&b, req.SenderInfo.ProcessChain)
			}
		}
	case approval.RequestTypeSSHSign:
		// Show key label and destination
		if len(req.Items) > 0 {
			fmt.Fprintf(&b, "<b>%s</b>", esc(req.Items[0].Label))
			if dest, ok := req.Items[0].Attributes["destination"]; ok && dest != "" {
				fmt.Fprintf(&b, " → %s", esc(dest))
			}
		}
		if len(req.SenderInfo.ProcessChain) > 0 {
			b.WriteString(" • <b>Process:</b> ")
			h.formatProcessChain(&b, req.SenderInfo.ProcessChain)
		}
	default:
		fmt.Fprintf(&b, "<b>Application:</b> %s", escapeMarkup(notificationApplication(req)))
		fmt.Fprintf(&b, " • <b>Request:</b> %s", escapeMarkup(requestActionLabel(req.Type)))
		fmt.Fprintf(&b, " • <b>Secret:</b> %s", escapeMarkup(requestSecretLabel(req)))
		if len(req.SenderInfo.ProcessChain) > 0 {
			b.WriteString(" • <b>Process:</b> ")
			h.formatProcessChain(&b, req.SenderInfo.ProcessChain)
		} else if req.SenderInfo.InvokerName != "" {
			fmt.Fprintf(&b, " • <b>Process:</b> %s[%d]", esc(req.SenderInfo.InvokerName), req.SenderInfo.PID)
		}
	}

	return b.String()
}
