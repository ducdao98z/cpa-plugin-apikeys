package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const testKey = "sk-test-0123456789abcdef"

func use(s *keyStore, key string, in, out int64, at time.Time) {
	s.record(pluginapi.UsageRecord{APIKey: key, Provider: "codex", Model: "gpt-5", Generate: true, RequestedAt: at,
		Detail: pluginapi.UsageDetail{InputTokens: in, OutputTokens: out}}, at)
}

func TestCallerScope(t *testing.T) {
	// CLIProxyAPI sdk/cliproxy/session.CallerScope("sk-test-0123456789abcdef"); the page computes the same id.
	if got := callerScope(" " + testKey + " "); got != "da09e7f6cc8e85e78aaf2c5a15965c31f7514d347da3d71ae007aaf557d7015d" {
		t.Fatalf("caller scope drifted from the core: %s", got)
	}
}

func TestLimits(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := &keyStore{keys: map[string]*keyEntry{}}
	id := callerScope(testKey)
	if status, _ := s.rejection(id, "gpt-5", "gpt-5", now); status != 0 {
		t.Fatal("a key without limits must pass")
	}
	if errSave := s.save(id, maskKey(testKey), "alice", 0, 1000, nil, nil, now); errSave != nil {
		t.Fatal(errSave)
	}
	use(s, testKey, 400, 200, now)
	if status, _ := s.rejection(id, "gpt-5", "gpt-5", now); status != 0 {
		t.Fatal("600 of 1000 tokens must pass")
	}
	use(s, testKey, 300, 100, now)
	status, body := s.rejection(id, "gpt-5", "gpt-5", now)
	if status != http.StatusForbidden || !strings.Contains(string(body), "token_quota_exceeded") {
		t.Fatalf("1000 of 1000 tokens: got %d %s", status, body)
	}
	if e := s.keys[id]; e.Masked != maskKey(testKey) || e.Models["gpt-5"].Requests != 2 || len(e.Recent) != 2 {
		t.Fatalf("usage not recorded per model and request: %+v", e)
	}
	if errReset := s.resetUsage(id); errReset != nil {
		t.Fatal(errReset)
	}
	if status, _ := s.rejection(id, "gpt-5", "gpt-5", now); status != 0 {
		t.Fatal("reset must restart the limit")
	}
	if errSave := s.save(id, "", "alice", now.UnixMilli(), 0, nil, nil, now); errSave != nil {
		t.Fatal(errSave)
	}
	if status, body := s.rejection(id, "gpt-5", "gpt-5", now); status != http.StatusForbidden || !strings.Contains(string(body), "api_key_expired") {
		t.Fatalf("expired key: got %d %s", status, body)
	}
	if status, _ := s.rejection(id, "gpt-5", "gpt-5", now.Add(-time.Second)); status != 0 {
		t.Fatal("a key must work until its expiry")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apikeys.json")
	now := time.Now()
	s := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := s.open(path); errOpen != nil {
		t.Fatal(errOpen)
	}
	id := callerScope(testKey)
	if errSave := s.save(id, maskKey(testKey), "alice", 0, 5000, []string{"gpt-5*"}, nil, now); errSave != nil {
		t.Fatal(errSave)
	}
	use(s, testKey, 100, 50, now)
	use(s, testKey, 1, 1, now.Add(-40*24*time.Hour)) // an older hour bucket is pruned on the next new hour
	use(s, testKey, 1, 1, now.Add(time.Hour))
	if errFlush := s.flush(); errFlush != nil {
		t.Fatal(errFlush)
	}
	reopened := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := reopened.open(path); errOpen != nil {
		t.Fatal(errOpen)
	}
	e := reopened.keys[id]
	if e == nil || e.Name != "alice" || e.TokenLimit != 5000 || e.Usage.Requests != 3 || e.Usage.Input != 102 || len(e.AllowedModels) != 1 {
		t.Fatalf("reloaded entry: %+v", e)
	}
	if len(e.Hours) != 2 {
		t.Fatalf("hour buckets older than %d hours must be pruned, got %d buckets", hourRetention, len(e.Hours))
	}
}

// The host sends the full request (base64 body included) and decodes the reply as RequestInterceptResponse.
func TestInterceptEnvelope(t *testing.T) {
	saved := store
	t.Cleanup(func() { store = saved })
	store = &keyStore{keys: map[string]*keyEntry{}}
	id := callerScope(testKey)
	if errSave := store.save(id, "", "", 1, 0, nil, nil, time.Now()); errSave != nil { // expired in 1970
		t.Fatal(errSave)
	}
	call := func(scope string) pluginapi.RequestInterceptResponse {
		raw, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: "r1", Model: "gpt-5", RequestedModel: "gpt-5", Body: []byte(`{"model":"gpt-5"}`), Metadata: map[string]any{"caller_scope": scope, "request_path": "/v1/chat/completions"}})
		out, errHandle := handleMethod(pluginabi.MethodRequestInterceptBefore, raw)
		if errHandle != nil {
			t.Fatal(errHandle)
		}
		var env pluginabi.Envelope
		var resp pluginapi.RequestInterceptResponse
		if json.Unmarshal(out, &env) != nil || !env.OK || json.Unmarshal(env.Result, &resp) != nil {
			t.Fatalf("bad envelope: %s", out)
		}
		return resp
	}
	if resp := call(id); !resp.Terminate || resp.StatusCode != http.StatusForbidden || !strings.Contains(string(resp.ResponseBody), "expired") {
		t.Fatalf("expired key passed: %+v", resp)
	}
	if resp := call(callerScope("another-key-123456")); resp.Terminate {
		t.Fatal("unmanaged key was refused")
	}
}

func TestMatchPattern(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"gpt-5", "gpt-5", true},
		{"gpt-5", "gpt-5-mini", false},
		{"gpt-5*", "gpt-5-mini", true},
		{"*", "anything/at-all", true},
		{"claude-*-4-5*", "claude-sonnet-4-5-20250929", true},
		{"openrouter/*", "openrouter/anthropic/claude", true}, // * crosses slashes
		{"ab*ba", "aba", false},                               // prefix and suffix may not overlap
		{"a*b*c", "abcbc", true},
		{"openai-compatible-*", "codex", false},
	} {
		if got := matchPattern(tc.pattern, tc.s); got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v", tc.pattern, tc.s, got)
		}
	}
}

func TestModelRules(t *testing.T) {
	now := time.Now()
	s := &keyStore{keys: map[string]*keyEntry{}}
	id := callerScope(testKey)
	if errSave := s.save(id, "", "", 0, 0, []string{"gpt-5*", "claude-sonnet-*"}, nil, now); errSave != nil {
		t.Fatal(errSave)
	}
	for _, tc := range []struct {
		requested, model string
		allowed          bool
	}{
		{"gpt-5-mini", "gpt-5-mini", true},
		{"GPT-5(high)", "gpt-5", true},        // case and thinking suffix are ignored
		{"sonnet", "claude-sonnet-4-5", true}, // an alias of an allowed model
		{"o3", "o3", false},
		{"claude-opus-4-1", "claude-opus-4-1", false},
		{"", "", false},
	} {
		status, body := s.rejection(id, tc.requested, tc.model, now)
		if (status == 0) != tc.allowed || (!tc.allowed && !strings.Contains(string(body), "model_not_allowed")) {
			t.Errorf("%q/%q: got %d %s", tc.requested, tc.model, status, body)
		}
	}
}

func TestPick(t *testing.T) {
	s := &keyStore{keys: map[string]*keyEntry{}}
	id := callerScope(testKey)
	cands := []schedulerCandidate{{ID: "codex-1", Provider: "codex"}, {ID: "claude-1", Provider: "Claude"}, {ID: "compat-1", Provider: "openai-compatible-cheap", Priority: 5}}
	pick := func(providers []string, session string, c []schedulerCandidate) pluginapi.SchedulerPickResponse {
		if errSave := s.save(id, "", "", 0, 0, nil, providers, time.Now()); errSave != nil {
			t.Fatal(errSave)
		}
		return s.pick(id, session, "gpt-5", c)
	}
	if r := pick(nil, "", cands); r.Handled {
		t.Fatal("an unrestricted key must leave the choice to the host")
	}
	if r := s.pick(callerScope("unknown-key-123456"), "", "gpt-5", cands); r.Handled {
		t.Fatal("an unknown key must leave the choice to the host")
	}
	if r := pick([]string{"codex", "claude", "openai-compatible-*"}, "", cands); r.Handled {
		t.Fatal("when every candidate is allowed the host must choose")
	}
	if r := pick([]string{"claude"}, "", cands); !r.Handled || r.AuthID != "claude-1" {
		t.Fatalf("provider filter: %+v", r)
	}
	if r := pick([]string{"codex", "openai-compatible-*"}, "", cands); r.AuthID != "compat-1" {
		t.Fatalf("the highest priority allowed credential must win: %+v", r)
	}
	if r := pick([]string{"gemini"}, "", cands); !r.Handled || !r.Reject {
		t.Fatalf("no allowed provider must reject: %+v", r)
	}
	two := append(cands, schedulerCandidate{ID: "claude-2", Provider: "claude"})
	first := pick([]string{"claude"}, "session-a", two).AuthID
	for i := 0; i < 5; i++ {
		if got := s.pick(id, "session-a", "gpt-5", two).AuthID; got != first {
			t.Fatalf("a session must keep its credential: %s then %s", first, got)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		seen[s.pick(id, "", "gpt-5", two).AuthID] = true
	}
	if !seen["claude-1"] || !seen["claude-2"] || seen["codex-1"] {
		t.Fatalf("requests without a session must rotate over allowed credentials: %v", seen)
	}
}
