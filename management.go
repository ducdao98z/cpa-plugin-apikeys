package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// ui is the key manager page, served as a plugin resource. It holds no data itself: every call it
// makes is authenticated with the management key.
//
//go:embed ui.html
var ui []byte

const (
	apiBase      = "/v0/management/apikeys"
	resourceBase = "/v0/resource/plugins/" + pluginIdentifier
	maxNameLen   = 120
)

type managementRoute struct {
	Method      string
	Path        string
	Description string
}

type resourceRoute struct {
	Path        string
	Menu        string
	Description string
}

// keySummary is a key without its history, for the list.
type keySummary struct {
	Masked     string   `json:"masked,omitempty"`
	Name       string   `json:"name,omitempty"`
	CreatedAt  int64    `json:"created_at,omitempty"`
	ExpiresAt  int64    `json:"expires_at,omitempty"`
	TokenLimit int64    `json:"token_limit,omitempty"`
	Usage      counters `json:"usage"`
	LastUsed   int64    `json:"last_used,omitempty"`
	Status     string   `json:"status,omitempty"`
}

type keyRequest struct {
	ID         string `json:"id"` // caller scope of the key
	Masked     string `json:"masked"`
	Name       string `json:"name"`
	ExpiresAt  int64  `json:"expires_at"`
	TokenLimit int64  `json:"token_limit"`
}

func managementRegistration() map[string]any {
	return map[string]any{
		"routes": []managementRoute{
			{Method: http.MethodGet, Path: apiBase, Description: "Limits and usage totals of every known client API key, by caller scope id."},
			{Method: http.MethodGet, Path: apiBase + "/detail", Description: "One key with its usage by model, hourly usage (31 days) and recent requests (?id)."},
			{Method: http.MethodPost, Path: apiBase + "/save", Description: "Create or update a key's name, expiry (unix ms) and token limit; usage is kept."},
			{Method: http.MethodPost, Path: apiBase + "/delete", Description: "Forget a key's limits and usage."},
			{Method: http.MethodPost, Path: apiBase + "/reset", Description: "Zero a key's usage, which restarts its token limit."},
		},
		"resources": []resourceRoute{{Path: "/ui", Menu: displayName, Description: "Add, edit and delete client API keys, with expiry dates, token limits and usage."}},
	}
}

func handleManagement(req pluginapi.ManagementRequest, now time.Time) pluginapi.ManagementResponse {
	reqPath := strings.TrimRight(req.Path, "/")
	if reqPath == resourceBase+"/ui" {
		return pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}, "Cache-Control": []string{"no-store"}},
			Body:       ui,
		}
	}
	switch req.Method + " " + reqPath {
	case "GET " + apiBase:
		store.mu.RLock()
		keys := make(map[string]keySummary, len(store.keys))
		for id, e := range store.keys {
			keys[id] = keySummary{Masked: e.Masked, Name: e.Name, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, TokenLimit: e.TokenLimit, Usage: e.Usage, LastUsed: e.LastUsed, Status: e.status(now)}
		}
		store.mu.RUnlock()
		return jsonResponse(http.StatusOK, map[string]any{"now": now.UnixMilli(), "keys": keys})
	case "GET " + apiBase + "/detail":
		store.mu.RLock()
		defer store.mu.RUnlock() // the history maps are marshaled in place
		e := store.keys[req.Query.Get("id")]
		if e == nil {
			return jsonResponse(http.StatusNotFound, map[string]any{"error": "unknown key"})
		}
		return jsonResponse(http.StatusOK, struct {
			*keyEntry
			Status string `json:"status,omitempty"`
			Now    int64  `json:"now"`
		}{e, e.status(now), now.UnixMilli()})
	case "POST " + apiBase + "/save", "POST " + apiBase + "/delete", "POST " + apiBase + "/reset":
		var body keyRequest
		if errUnmarshal := json.Unmarshal(req.Body, &body); errUnmarshal != nil {
			return jsonResponse(http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		}
		if msg := validate(&body); msg != "" {
			return jsonResponse(http.StatusBadRequest, map[string]any{"error": msg})
		}
		var errApply error
		switch {
		case strings.HasSuffix(reqPath, "/save"):
			errApply = store.save(body.ID, body.Masked, body.Name, body.ExpiresAt, body.TokenLimit, now)
		case strings.HasSuffix(reqPath, "/delete"):
			errApply = store.remove(body.ID)
		default:
			errApply = store.resetUsage(body.ID)
		}
		if errApply != nil {
			return jsonResponse(http.StatusInternalServerError, map[string]any{"error": errApply.Error()})
		}
		return jsonResponse(http.StatusOK, map[string]any{"status": "ok"})
	}
	return jsonResponse(http.StatusNotFound, map[string]any{"error": "unknown route"})
}

func validate(r *keyRequest) string {
	r.ID = strings.ToLower(strings.TrimSpace(r.ID))
	r.Name = strings.TrimSpace(r.Name)
	r.Masked = strings.TrimSpace(r.Masked)
	if _, errDecode := hex.DecodeString(r.ID); errDecode != nil || len(r.ID) != 64 {
		return "id must be the key's caller scope (64 hex characters)"
	}
	switch {
	case utf8.RuneCountInString(r.Name) > maxNameLen:
		return "name is too long"
	case len(r.Masked) > 32:
		return "masked key is too long"
	case r.ExpiresAt < 0 || r.TokenLimit < 0:
		return "expires_at and token_limit must not be negative"
	}
	return ""
}

func jsonResponse(status int, v any) pluginapi.ManagementResponse {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		status, raw = http.StatusInternalServerError, []byte(`{"error":"encode response"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json"}, "Cache-Control": []string{"no-store"}},
		Body:       raw,
	}
}
