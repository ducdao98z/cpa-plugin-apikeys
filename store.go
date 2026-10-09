package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	recentLimit   = 20              // recent requests kept per key
	hourRetention = 31 * 24         // hourly buckets kept per key; the page charts the last 30 days
	flushDelay    = 5 * time.Second // usage is written in batches, key changes at once
	statusExpired = "expired"
	statusQuota   = "quota"
)

// counters sums finished requests. Input includes cached tokens and output includes reasoning,
// so input + output is what a token limit counts.
type counters struct {
	Requests  int64 `json:"requests"`
	Failed    int64 `json:"failed,omitempty"`
	Input     int64 `json:"input"`
	Output    int64 `json:"output"`
	Cached    int64 `json:"cached,omitempty"`
	Reasoning int64 `json:"reasoning,omitempty"`
}

func (c *counters) add(o counters) {
	c.Requests += o.Requests
	c.Failed += o.Failed
	c.Input += o.Input
	c.Output += o.Output
	c.Cached += o.Cached
	c.Reasoning += o.Reasoning
}

type recentRequest struct {
	TS        int64  `json:"ts"` // request start, unix ms
	Model     string `json:"model"`
	Provider  string `json:"provider,omitempty"`
	Input     int64  `json:"input"`
	Output    int64  `json:"output"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Status    int    `json:"status,omitempty"`
	Failed    bool   `json:"failed,omitempty"`
}

// keyEntry holds the limits and usage of one client API key. Entries are keyed by the key's caller
// scope (see callerScope), so raw keys never reach this plugin or its file.
type keyEntry struct {
	Masked     string               `json:"masked,omitempty"`
	Name       string               `json:"name,omitempty"`
	CreatedAt  int64                `json:"created_at,omitempty"`  // unix ms
	ExpiresAt  int64                `json:"expires_at,omitempty"`  // unix ms, 0 = never
	TokenLimit int64                `json:"token_limit,omitempty"` // input + output tokens, 0 = unlimited
	Usage      counters             `json:"usage"`
	LastUsed   int64                `json:"last_used,omitempty"`
	Models     map[string]*counters `json:"models,omitempty"`
	Hours      map[int64]*counters  `json:"hours,omitempty"`  // unix hour -> usage
	Recent     []recentRequest      `json:"recent,omitempty"` // oldest first
}

// status reports why the key is refused, or "" while it may be used.
func (e *keyEntry) status(now time.Time) string {
	switch {
	case e.ExpiresAt > 0 && now.UnixMilli() >= e.ExpiresAt:
		return statusExpired
	case e.TokenLimit > 0 && e.Usage.Input+e.Usage.Output >= e.TokenLimit:
		return statusQuota
	}
	return ""
}

type storeFile struct {
	Keys map[string]*keyEntry `json:"keys"`
}

// keyStore keeps every entry in memory and rewrites the data file (small: no per-request log).
type keyStore struct {
	mu      sync.RWMutex
	writeMu sync.Mutex // orders file writes
	path    string     // empty while the data file is unreadable: nothing is written over it
	openErr error
	keys    map[string]*keyEntry
	dirty   bool
	pending bool // a delayed flush is scheduled
}

func (s *keyStore) open(path string) error {
	s.mu.RLock()
	same := s.path == path
	s.mu.RUnlock()
	if same {
		return nil
	}
	if errFlush := s.flush(); errFlush != nil {
		hostLog("warn", "apikeys: "+errFlush.Error())
	}
	keys := map[string]*keyEntry{}
	raw, errRead := os.ReadFile(path)
	if errRead == nil {
		var f storeFile
		errRead = json.Unmarshal(raw, &f)
		if f.Keys != nil {
			keys = f.Keys
		}
	} else if errors.Is(errRead, os.ErrNotExist) {
		errRead = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if errRead != nil {
		s.path, s.openErr = "", fmt.Errorf("read %s: %w", path, errRead)
		return s.openErr
	}
	s.path, s.openErr, s.keys, s.dirty = path, nil, keys, false
	return nil
}

// flush writes pending changes now.
func (s *keyStore) flush() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	s.pending = false
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	// ponytail: the whole file is rewritten, fine for hundreds of keys; append a log past that.
	raw, errWrite := json.Marshal(storeFile{Keys: s.keys})
	path := s.path
	s.dirty = false
	s.mu.Unlock()
	if errWrite == nil {
		errWrite = writeFileAtomic(path, raw)
	}
	if errWrite != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("write %s: %w", path, errWrite)
	}
	return nil
}

func writeFileAtomic(path string, raw []byte) error {
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o755); errMkdir != nil {
		return errMkdir
	}
	tmp := path + ".tmp"
	if errWrite := os.WriteFile(tmp, raw, 0o600); errWrite != nil {
		return errWrite
	}
	return os.Rename(tmp, path)
}

// commit writes a key change at once and reports a data file that could not be loaded.
func (s *keyStore) commit() error {
	if errFlush := s.flush(); errFlush != nil {
		return errFlush
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.openErr != nil {
		return fmt.Errorf("applied until restart, not saved: %w", s.openErr)
	}
	return nil
}

// touch marks the store dirty and schedules a write; callers hold s.mu.
func (s *keyStore) touch() {
	s.dirty = true
	if s.pending {
		return
	}
	s.pending = true
	time.AfterFunc(flushDelay, func() {
		if errFlush := s.flush(); errFlush != nil {
			hostLog("warn", "apikeys: "+errFlush.Error())
		}
	})
}

// rejection returns the HTTP status and body that refuse a request, or 0 when it may proceed.
// Keys without an entry are unlimited.
func (s *keyStore) rejection(scope string, now time.Time) (int, []byte) {
	if scope == "" {
		return 0, nil
	}
	s.mu.RLock()
	e := s.keys[scope]
	var status, message string
	if e != nil {
		switch status = e.status(now); status {
		case statusExpired:
			message = "This API key expired on " + time.UnixMilli(e.ExpiresAt).UTC().Format("2006-01-02 15:04 UTC") + "."
		case statusQuota:
			message = fmt.Sprintf("This API key has used its token limit (%d of %d tokens).", e.Usage.Input+e.Usage.Output, e.TokenLimit)
		}
	}
	s.mu.RUnlock()
	if status == "" {
		return 0, nil
	}
	code := "api_key_expired"
	if status == statusQuota {
		code = "token_quota_exceeded"
	}
	// One body that Anthropic- and OpenAI-style clients both read. 403, not 429: a retry cannot succeed.
	body, _ := json.Marshal(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": "permission_error", "code": code, "message": message},
	})
	return http.StatusForbidden, body
}

// record adds one finished model call to its key.
func (s *keyStore) record(u pluginapi.UsageRecord, now time.Time) {
	key := strings.TrimSpace(u.APIKey)
	if key == "" || !u.Generate {
		return // no client key, or a non-generating call such as token counting
	}
	input, cached, output, reasoning := normalizeTokens(u.Detail, u.Provider, u.ExecutorType)
	c := counters{Requests: 1, Input: input, Output: output, Cached: cached, Reasoning: reasoning}
	rr := recentRequest{Model: firstNonEmpty(u.Alias, u.Model, "unknown"), Provider: strings.TrimSpace(u.Provider), Input: input, Output: output, LatencyMs: u.Latency.Milliseconds(), Status: http.StatusOK}
	if u.Failed {
		c.Failed = 1
		rr.Failed, rr.Status = true, u.Failure.StatusCode
	}
	at := u.RequestedAt
	if at.IsZero() {
		at = now
	}
	rr.TS = at.UnixMilli()
	hour := at.Unix() / 3600

	id := callerScope(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.keys[id]
	if e == nil {
		e = &keyEntry{Masked: maskKey(key), CreatedAt: now.UnixMilli()}
		s.keys[id] = e
	}
	e.Usage.add(c)
	e.LastUsed = max(e.LastUsed, rr.TS)
	e.Models = addTo(e.Models, rr.Model, c)
	if _, ok := e.Hours[hour]; !ok {
		for h := range e.Hours {
			if h <= hour-hourRetention {
				delete(e.Hours, h)
			}
		}
	}
	e.Hours = addTo(e.Hours, hour, c)
	e.Recent = append(e.Recent, rr)
	if extra := len(e.Recent) - recentLimit; extra > 0 {
		e.Recent = append([]recentRequest(nil), e.Recent[extra:]...)
	}
	s.touch()
}

func addTo[K comparable](m map[K]*counters, k K, c counters) map[K]*counters {
	if m == nil {
		m = map[K]*counters{}
	}
	if m[k] == nil {
		m[k] = &counters{}
	}
	m[k].add(c)
	return m
}

// save creates or updates the limits of a key; its usage is kept.
func (s *keyStore) save(id, masked, name string, expiresAt, tokenLimit int64, now time.Time) error {
	s.mu.Lock()
	e := s.keys[id]
	if e == nil {
		e = &keyEntry{CreatedAt: now.UnixMilli()}
		s.keys[id] = e
	}
	if masked != "" {
		e.Masked = masked
	}
	e.Name, e.ExpiresAt, e.TokenLimit = name, expiresAt, tokenLimit
	s.touch()
	s.mu.Unlock()
	return s.commit()
}

func (s *keyStore) remove(id string) error {
	s.mu.Lock()
	delete(s.keys, id)
	s.touch()
	s.mu.Unlock()
	return s.commit()
}

// resetUsage zeroes what the token limit counts, along with the key's history.
func (s *keyStore) resetUsage(id string) error {
	s.mu.Lock()
	if e := s.keys[id]; e != nil {
		e.Usage, e.LastUsed, e.Models, e.Hours, e.Recent = counters{}, 0, nil, nil, nil
	}
	s.touch()
	s.mu.Unlock()
	return s.commit()
}

// callerScope matches the caller_scope request metadata CLIProxyAPI derives from the client API key
// (sdk/cliproxy/session CallerScope); the page computes the same id in the browser.
func callerScope(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + key))
	return hex.EncodeToString(sum[:])
}

// normalizeTokens returns cache-inclusive input and reasoning-inclusive output totals, as the usage
// plugin does; the provider semantics mirror CLIProxyAPI sdk/cliproxy/usage/accounting.go.
func normalizeTokens(d pluginapi.UsageDetail, provider, executor string) (input, cached, output, reasoning int64) {
	input, output = d.InputTokens, d.OutputTokens
	cached, reasoning = d.CacheReadTokens, d.ReasoningTokens
	cacheWrite := d.CacheCreationTokens
	if cached == 0 && d.CachedTokens > 0 && input == 0 && output == 0 && reasoning == 0 && cacheWrite == 0 && d.TotalTokens == 0 {
		cached = d.CachedTokens
	}
	p := strings.ToLower(strings.TrimSpace(provider))
	e := strings.ToLower(strings.TrimSpace(executor))
	both := p + " " + e
	switch {
	case e == "openaicompatexecutor" || p == "openai-compatibility" || strings.HasPrefix(p, "openai-compatible-"):
	case strings.Contains(both, "claude") || strings.Contains(both, "anthropic"):
		input += cached + cacheWrite // Anthropic reports uncached input and reasoning separately
		output += reasoning
	case containsAny(both, "gemini", "aistudio", "antigravity", "vertex", "interaction"):
		output += reasoning // Gemini reports thoughts separately; input already includes cache
	}
	return input, cached, output, reasoning
}

// maskKey keeps the head and tail of a key, as the usage plugin and the page do.
func maskKey(key string) string {
	switch {
	case key == "":
		return ""
	case len(key) <= 12:
		return key[:1] + "***"
	default:
		return key[:8] + "***" + key[len(key)-4:]
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
