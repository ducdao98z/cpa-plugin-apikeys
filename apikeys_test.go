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
	if status, _ := s.rejection(id, now); status != 0 {
		t.Fatal("a key without limits must pass")
	}
	if errSave := s.save(id, maskKey(testKey), "alice", 0, 1000, now); errSave != nil {
		t.Fatal(errSave)
	}
	use(s, testKey, 400, 200, now)
	if status, _ := s.rejection(id, now); status != 0 {
		t.Fatal("600 of 1000 tokens must pass")
	}
	use(s, testKey, 300, 100, now)
	status, body := s.rejection(id, now)
	if status != http.StatusForbidden || !strings.Contains(string(body), "token_quota_exceeded") {
		t.Fatalf("1000 of 1000 tokens: got %d %s", status, body)
	}
	if e := s.keys[id]; e.Masked != maskKey(testKey) || e.Models["gpt-5"].Requests != 2 || len(e.Recent) != 2 {
		t.Fatalf("usage not recorded per model and request: %+v", e)
	}
	if errReset := s.resetUsage(id); errReset != nil {
		t.Fatal(errReset)
	}
	if status, _ := s.rejection(id, now); status != 0 {
		t.Fatal("reset must restart the limit")
	}
	if errSave := s.save(id, "", "alice", now.UnixMilli(), 0, now); errSave != nil {
		t.Fatal(errSave)
	}
	if status, body := s.rejection(id, now); status != http.StatusForbidden || !strings.Contains(string(body), "api_key_expired") {
		t.Fatalf("expired key: got %d %s", status, body)
	}
	if status, _ := s.rejection(id, now.Add(-time.Second)); status != 0 {
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
	if errSave := s.save(id, maskKey(testKey), "alice", 0, 5000, now); errSave != nil {
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
	if e == nil || e.Name != "alice" || e.TokenLimit != 5000 || e.Usage.Requests != 3 || e.Usage.Input != 102 {
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
	if errSave := store.save(id, "", "", 1, 0, time.Now()); errSave != nil { // expired in 1970
		t.Fatal(errSave)
	}
	call := func(scope string) pluginapi.RequestInterceptResponse {
		raw, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: "r1", Body: []byte(`{"model":"gpt-5"}`), Metadata: map[string]any{"caller_scope": scope, "request_path": "/v1/chat/completions"}})
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
