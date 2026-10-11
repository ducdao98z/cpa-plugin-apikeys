package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	if errSave := s.save(id, maskKey(testKey), "alice", 0, 1000, 0, nil, now); errSave != nil {
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
	if errSave := s.save(id, "", "alice", now.UnixMilli(), 0, 0, nil, now); errSave != nil {
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
	path := filepath.Join(t.TempDir(), "apikeys.db")
	now := time.Now()
	s := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := s.open(path); errOpen != nil {
		t.Fatal(errOpen)
	}
	id, other := callerScope(testKey), callerScope("sk-other-0123456789")
	if errSave := s.save(id, maskKey(testKey), "alice", 0, 5000, 60, []string{"gpt-5*"}, now); errSave != nil {
		t.Fatal(errSave)
	}
	for _, name := range []string{path, path + "-wal"} {
		if info, errStat := os.Stat(name); errStat != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
			t.Fatalf("%s must be owner-only: %v %v", name, info, errStat)
		}
	}
	use(s, testKey, 100, 50, now)
	use(s, testKey, 1, 1, now.Add(-40*24*time.Hour)) // kept on disk, not loaded: older than hourRetention
	use(s, testKey, 1, 1, now.Add(time.Hour))
	for i := 0; i < recentLimit+5; i++ {
		use(s, "sk-other-0123456789", 1, 0, now)
	}
	s.close() // as on quiesce: a register reopens the database
	if errOpen := s.open(path); errOpen != nil {
		t.Fatal(errOpen)
	}
	e := s.keys[id]
	if e == nil || e.Name != "alice" || e.TokenLimit != 5000 || e.RPMLimit != 60 || e.Usage.Requests != 3 || e.Usage.Input != 102 || e.Usage.Output != 52 ||
		len(e.AllowedModels) != 1 || e.Models["gpt-5"].Requests != 3 || len(e.Recent) != 3 || e.Recent[2].Input != 1 {
		t.Fatalf("reloaded entry: %+v", e)
	}
	if len(e.Hours) != 2 {
		t.Fatalf("hour buckets older than %d hours must not be loaded, got %d buckets", hourRetention, len(e.Hours))
	}
	var stored int
	if errCount := s.db.QueryRow("SELECT COUNT(*) FROM key_hours WHERE scope = ?", id).Scan(&stored); errCount != nil || stored != 3 {
		t.Fatalf("the database keeps every hour bucket: %d, %v", stored, errCount)
	}
	if o := s.keys[other]; o == nil || o.Usage.Requests != recentLimit+5 || len(o.Recent) != recentLimit || o.Masked != maskKey("sk-other-0123456789") {
		t.Fatalf("unmanaged key: %+v", o)
	}

	if errReset := s.resetUsage(id); errReset != nil {
		t.Fatal(errReset)
	}
	if errRemove := s.remove(other); errRemove != nil {
		t.Fatal(errRemove)
	}
	s.close()
	reopened := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := reopened.open(path); errOpen != nil {
		t.Fatal(errOpen)
	}
	defer reopened.close()
	if e = reopened.keys[id]; e == nil || e.Usage != (counters{}) || e.LastUsed != 0 || e.Models != nil || e.Hours != nil || e.Recent != nil || e.TokenLimit != 5000 {
		t.Fatalf("reset entry: %+v", e)
	}
	if reopened.keys[other] != nil {
		t.Fatal("removed key came back")
	}
}

func TestImportJSON(t *testing.T) {
	dir := t.TempDir()
	db, legacy := filepath.Join(dir, "apikeys.db"), filepath.Join(dir, "apikeys.json")
	id, kept := callerScope(testKey), callerScope("sk-kept-0123456789")
	now := time.Now()
	s := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := s.open(db); errOpen != nil {
		t.Fatal(errOpen)
	}
	if errSave := s.save(kept, "", "from the database", 0, 0, 0, nil, now); errSave != nil {
		t.Fatal(errSave)
	}
	s.close()
	hour := now.Unix() / 3600
	raw, _ := json.Marshal(storeFile{Keys: map[string]*keyEntry{
		id: {Masked: maskKey(testKey), Name: "alice", TokenLimit: 900, AllowedModels: []string{"gpt-5*"}, LastUsed: 2,
			Usage:  counters{Requests: 2, Input: 30, Output: 10},
			Models: map[string]*counters{"gpt-5": {Requests: 2, Input: 30, Output: 10}},
			Hours:  map[int64]*counters{hour: {Requests: 2, Input: 30, Output: 10}},
			Recent: []recentRequest{{TS: 1, Model: "gpt-5", Input: 10}, {TS: 2, Model: "gpt-5", Input: 20, Failed: true, Status: 500}}},
		kept: {Name: "from the file"},
	}})
	if errWrite := os.WriteFile(legacy, raw, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}

	s = &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := s.open(legacy); errOpen != nil { // configs before 0.4.0 name the .json file
		t.Fatal(errOpen)
	}
	defer s.close()
	if _, errStat := os.Stat(legacy); !errors.Is(errStat, os.ErrNotExist) {
		t.Fatal("data file left in place, so it would be imported again")
	}
	if _, errStat := os.Stat(legacy + ".imported"); errStat != nil {
		t.Fatalf("data file not kept: %v", errStat)
	}
	e := s.keys[id]
	if e == nil || e.Name != "alice" || e.TokenLimit != 900 || e.AllowedModels[0] != "gpt-5*" || e.Usage.Input != 30 || e.LastUsed != 2 ||
		e.Models["gpt-5"].Requests != 2 || e.Hours[hour].Output != 10 || len(e.Recent) != 2 || !e.Recent[1].Failed || e.Recent[1].Status != 500 {
		t.Fatalf("imported entry: %+v", e)
	}
	if s.keys[kept].Name != "from the database" {
		t.Fatal("the import overwrote a key the database already had")
	}
}

func TestUnreadableDataIsNotOverwritten(t *testing.T) {
	legacy := filepath.Join(t.TempDir(), "apikeys.json")
	if errWrite := os.WriteFile(legacy, []byte(`{"keys":`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	s := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen := s.open(legacy); errOpen == nil {
		t.Fatal("a torn data file was accepted")
	}
	id := callerScope(testKey)
	if errSave := s.save(id, "", "", 1, 0, 0, nil, time.Now()); errSave == nil || !strings.Contains(errSave.Error(), "not saved") {
		t.Fatalf("save must report it was not stored: %v", errSave)
	}
	if status, _ := s.rejection(id, "gpt-5", "gpt-5", time.Now()); status != http.StatusForbidden {
		t.Fatal("a limit saved while the data is unreadable must still apply until restart")
	}
	if raw, _ := os.ReadFile(legacy); string(raw) != `{"keys":` {
		t.Fatalf("data file changed: %s", raw)
	}
}

// The host sends the full request (base64 body included) and decodes the reply as RequestInterceptResponse.
func TestInterceptEnvelope(t *testing.T) {
	saved := store
	t.Cleanup(func() { store = saved })
	store = &keyStore{keys: map[string]*keyEntry{}}
	id := callerScope(testKey)
	if errSave := store.save(id, "", "", 1, 0, 0, nil, time.Now()); errSave != nil { // expired in 1970
		t.Fatal(errSave)
	}
	call := func(scope string, path ...string) pluginapi.RequestInterceptResponse {
		route := "/v1/chat/completions"
		if len(path) > 0 {
			route = path[0]
		}
		raw, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: "r1", Model: "gpt-5", RequestedModel: "gpt-5", Body: []byte(`{"model":"gpt-5"}`), Metadata: map[string]any{"caller_scope": scope, "request_path": route}})
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

	limited := callerScope("sk-limited-0123456789")
	if errSave := store.save(limited, "", "", 0, 0, 1, nil, time.Now()); errSave != nil {
		t.Fatal(errSave)
	}
	if resp := call(limited); resp.Terminate {
		t.Fatal("first request of the minute was refused")
	}
	if resp := call(limited, "/v1/messages/count_tokens"); resp.Terminate {
		t.Fatal("token counting must not hit the RPM limit")
	}
	resp := call(limited)
	if retry, _ := strconv.Atoi(resp.ResponseHeaders.Get("Retry-After")); !resp.Terminate || resp.StatusCode != http.StatusTooManyRequests || retry < 1 || retry > 60 ||
		!strings.Contains(string(resp.ResponseBody), "rate_limit_error") {
		t.Fatalf("second request of the minute: %+v %s", resp, resp.ResponseBody)
	}
}

func TestRPMLimit(t *testing.T) {
	start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s := &keyStore{keys: map[string]*keyEntry{}}
	id := callerScope(testKey)
	if errSave := s.save(id, "", "", 0, 0, 3, nil, start); errSave != nil {
		t.Fatal(errSave)
	}
	at := func(d time.Duration) int64 { retry, _ := s.throttle(id, start.Add(d)); return retry }
	for _, d := range []time.Duration{0, 10 * time.Second, 20 * time.Second} {
		if retry := at(d); retry != 0 {
			t.Fatalf("request at +%s refused under the limit (retry %d)", d, retry)
		}
	}
	if retry := at(30 * time.Second); retry != 30 {
		t.Fatalf("4th request in a minute: retry %d, want 30 (until the first leaves the window)", retry)
	}
	if retry := at(59*time.Second + 500*time.Millisecond); retry != 1 {
		t.Fatalf("retry rounds up to whole seconds: got %d", retry)
	}
	if retry := at(time.Minute); retry != 0 {
		t.Fatal("a slot frees up once the first request is a minute old; refused requests take none")
	}
	if retry, body := s.throttle(id, start.Add(time.Minute)); retry != 10 || !strings.Contains(string(body), "rate_limit_exceeded") {
		t.Fatalf("full window again: retry %d %s", retry, body)
	}
	if errSave := s.save(id, "", "", 0, 0, 1, nil, start); errSave != nil { // lowered: 3 admitted, 1 allowed
		t.Fatal(errSave)
	}
	if retry := at(time.Minute + 5*time.Second); retry != 55 {
		t.Fatalf("lowered limit waits until fewer than the limit remain, here the newest (+60s): retry %d, want 55", retry)
	}
	if retry, _ := s.throttle(callerScope("another-key-123456"), start); retry != 0 {
		t.Fatal("a key without an RPM limit was throttled")
	}
}

// Databases of 0.4.x have no rpm_limit column; opening one adds it and keeps the keys.
func TestMigrateRPMColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apikeys.db")
	old := strings.Replace(schema, "rpm_limit      INTEGER NOT NULL DEFAULT 0,\n\t", "", 1)
	if old == schema {
		t.Fatal("rpm_limit not found in the schema")
	}
	db, errOpen := sql.Open("sqlite", path)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	if _, errExec := db.Exec(old + "INSERT INTO keys (scope, name, token_limit) VALUES ('" + callerScope(testKey) + "', 'alice', 7);"); errExec != nil {
		t.Fatal(errExec)
	}
	_ = db.Close()
	s := &keyStore{keys: map[string]*keyEntry{}}
	if errOpen = s.open(path); errOpen != nil {
		t.Fatal(errOpen)
	}
	defer s.close()
	if e := s.keys[callerScope(testKey)]; e == nil || e.Name != "alice" || e.TokenLimit != 7 || e.RPMLimit != 0 {
		t.Fatalf("migrated entry: %+v", e)
	}
	if errSave := s.save(callerScope(testKey), "", "alice", 0, 7, 30, nil, time.Now()); errSave != nil {
		t.Fatal(errSave)
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
	if errSave := s.save(id, "", "", 0, 0, 0, []string{"gpt-5*", "claude-sonnet-*"}, now); errSave != nil {
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
