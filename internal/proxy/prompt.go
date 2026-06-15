package proxy

import (
	"context"

	"github.com/godbus/dbus/v5"
	dbustypes "github.com/nikicat/secrets-dispatcher/internal/dbus"
	"github.com/nikicat/secrets-dispatcher/internal/logging"
)

// PromptHandler forwards Secret Service Prompt objects from the front bus to the backend.
// Backends such as GNOME Keyring return prompt object paths when a collection/item needs
// unlocking. Clients then call org.freedesktop.Secret.Prompt.Prompt or Dismiss on that
// object path, so the proxy must expose the interface for /org/freedesktop/secrets/prompt/*.
type PromptHandler struct {
	localConn *dbus.Conn
	logger    *logging.Logger
}

func NewPromptHandler(localConn *dbus.Conn, logger *logging.Logger) *PromptHandler {
	return &PromptHandler{localConn: localConn, logger: logger}
}

// Prompt starts the prompt interaction.
// Signature: Prompt(window_id String)
func (p *PromptHandler) Prompt(msg dbus.Message, windowID string) *dbus.Error {
	path := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	obj := p.localConn.Object(dbustypes.BusName, path)
	call := obj.Call(dbustypes.PromptInterface+".Prompt", 0, windowID)
	if call.Err != nil {
		p.logger.LogMethod(context.Background(), "Prompt.Prompt", map[string]any{"path": string(path)}, "error", call.Err)
		return &dbus.Error{Name: "org.freedesktop.DBus.Error.Failed", Body: []any{call.Err.Error()}}
	}
	p.logger.LogMethod(context.Background(), "Prompt.Prompt", map[string]any{"path": string(path)}, "ok", nil)
	return nil
}

// Dismiss dismisses the prompt interaction.
// Signature: Dismiss()
func (p *PromptHandler) Dismiss(msg dbus.Message) *dbus.Error {
	path := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	obj := p.localConn.Object(dbustypes.BusName, path)
	call := obj.Call(dbustypes.PromptInterface+".Dismiss", 0)
	if call.Err != nil {
		p.logger.LogMethod(context.Background(), "Prompt.Dismiss", map[string]any{"path": string(path)}, "error", call.Err)
		return &dbus.Error{Name: "org.freedesktop.DBus.Error.Failed", Body: []any{call.Err.Error()}}
	}
	p.logger.LogMethod(context.Background(), "Prompt.Dismiss", map[string]any{"path": string(path)}, "ok", nil)
	return nil
}
