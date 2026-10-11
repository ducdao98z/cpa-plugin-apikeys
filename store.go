package main

import (
	"crypto/sha256"
	"database/sql"
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
	_ "modernc.org/sqlite" // pure Go: every platform builds without a C SQLite
)

const (
	recentLimit   = 20      // recent requests kept per key
	hourRetention = 31 * 24 // hourly buckets kept in memory per key, for the page's 30 days; the database keeps all
	statusExpired = "expired"
	statusQuota   = "quota"
	rpmWindow     = 60_000 // ms: an RPM limit counts the requests admitted in the last minute
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

// fields points at the counters in counterColumns order, for scanning and inserting alike.
func (c *counters) fields() []any {
	return []any{&c.Requests, &c.Failed, &c.Input, &c.Output, &c.Cached, &c.Reasoning}
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

// fields points at the request's values in recentColumns order.
func (r *recentRequest) fields() []any {
	return []any{&r.TS, &r.Model, &r.Provider, &r.Input, &r.Output, &r.LatencyMs, &r.Status, &r.Failed}
}

// keyEntry holds the limits and usage of one client API key. Entries are keyed by the key's caller
// scope (see callerScope), so raw keys never reach this plugin or its database.
type keyEntry struct {
	Masked     string `json:"masked,omitempty"`
	Name       string `json:"name,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`  // unix ms
	ExpiresAt  int64  `json:"expires_at,omitempty"`  // unix ms, 0 = never
	TokenLimit int64  `json:"token_limit,omitempty"` // input + output tokens, 0 = unlimited
	RPMLimit   int64  `json:"rpm_limit,omitempty"`   // model requests per minute, 0 = unlimited
	// Allowed models: lower-case patterns (* = any run of characters); empty allows every model.
	AllowedModels []string             `json:"allowed_models,omitempty"`
	Usage         counters             `json:"usage"`
	LastUsed      int64                `json:"last_used,omitempty"`
	Models        map[string]*counters `json:"models,omitempty"`
	Hours         map[int64]*counters  `json:"hours,omitempty"`  // unix hour -> usage
	Recent        []recentRequest      `json:"recent,omitempty"` // oldest first

	admitted []int64 // unix ms of the requests admitted in the last rpmWindow, oldest first; guarded by keyStore.rateMu
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

// storeFile is the JSON data file of versions before 0.4.0.
type storeFile struct {
	Keys map[string]*keyEntry `json:"keys"`
}

const (
	keyColumns     = "scope, masked, name, created_at, expires_at, token_limit, rpm_limit, allowed_models"
	counterColumns = "requests, failed, input, output, cached, reasoning"
	recentColumns  = "ts, model, provider, input, output, latency_ms, status, failed"
	counterDefs    = "requests INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, input INTEGER NOT NULL DEFAULT 0, " +
		"output INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0, reasoning INTEGER NOT NULL DEFAULT 0"
	// addCounters adds the counters of an upsert to the row it conflicts with.
	addCounters = "requests = requests + excluded.requests, failed = failed + excluded.failed, input = input + excluded.input, " +
		"output = output + excluded.output, cached = cached + excluded.cached, reasoning = reasoning + excluded.reasoning"
)

// Keys are stored by caller scope, never as raw keys; allowed_models is a JSON array of patterns.
const schema = `
CREATE TABLE IF NOT EXISTS keys (
	scope          TEXT PRIMARY KEY,
	masked         TEXT    NOT NULL DEFAULT '',
	name           TEXT    NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL DEFAULT 0,
	expires_at     INTEGER NOT NULL DEFAULT 0,
	token_limit    INTEGER NOT NULL DEFAULT 0,
	rpm_limit      INTEGER NOT NULL DEFAULT 0,
	allowed_models TEXT    NOT NULL DEFAULT '',
	last_used      INTEGER NOT NULL DEFAULT 0,
	` + counterDefs + `
);
CREATE TABLE IF NOT EXISTS key_models (scope TEXT NOT NULL, model TEXT NOT NULL, ` + counterDefs + `, PRIMARY KEY (scope, model));
CREATE TABLE IF NOT EXISTS key_hours (scope TEXT NOT NULL, hour INTEGER NOT NULL, ` + counterDefs + `, PRIMARY KEY (scope, hour));
CREATE TABLE IF NOT EXISTS key_recent (
	scope      TEXT    NOT NULL,
	ts         INTEGER NOT NULL,
	model      TEXT    NOT NULL,
	provider   TEXT    NOT NULL,
	input      INTEGER NOT NULL,
	output     INTEGER NOT NULL,
	latency_ms INTEGER NOT NULL,
	status     INTEGER NOT NULL,
	failed     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS key_recent_scope ON key_recent (scope);`

// keyStore keeps every entry in memory, where the limit check reads it, and writes each change
// through to a SQLite database.
type keyStore struct {
	mu      sync.RWMutex // guards keys and their entries; never held across database calls
	writeMu sync.Mutex   // orders changes, so they reach the database in the order they reached memory
	rateMu  sync.Mutex   // guards the entries' admitted times; taken inside mu
	path    string
	db      *sql.DB // nil while closed or unusable: changes then stay in memory
	openErr error
	keys    map[string]*keyEntry
}

// open keeps limits and usage in the SQLite database at path. A .json path (configs before 0.4.0) stands
// for the .db next to it, and a JSON data file next to the database is imported into it once.
func (s *keyStore) open(path string) error {
	legacy := strings.TrimSuffix(path, filepath.Ext(path)) + ".json"
	if path == legacy {
		path = strings.TrimSuffix(path, ".json") + ".db"
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.path == path && s.db != nil {
		return nil
	}
	s.closeLocked()
	s.path = path
	db, errOpen := openDB(path)
	var keys map[string]*keyEntry
	if errOpen == nil {
		if errOpen = importJSON(db, legacy); errOpen == nil {
			keys, errOpen = readKeys(db, time.Now())
		}
		if errOpen != nil {
			_ = db.Close()
		}
	}
	if errOpen != nil {
		// Unusable data is never written over; the keys in memory stay as they were.
		s.openErr = fmt.Errorf("open %s: %w", path, errOpen)
		return s.openErr
	}
	s.db, s.openErr = db, nil
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return nil
}

func openDB(path string) (*sql.DB, error) {
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o755); errMkdir != nil {
		return nil, errMkdir
	}
	// Owner-only, as the JSON file was; SQLite gives its -wal and -shm files the same mode.
	file, errCreate := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if errCreate != nil {
		return nil, errCreate
	}
	_ = file.Close()
	// WAL keeps reads beside writes; NORMAL skips an fsync per request.
	db, errOpen := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if errOpen != nil {
		return nil, errOpen
	}
	if _, errSchema := db.Exec(schema); errSchema != nil {
		_ = db.Close()
		return nil, errSchema
	}
	// Databases of 0.4.x have no rpm_limit column.
	var hasRPM bool
	errMigrate := db.QueryRow("SELECT COUNT(*) > 0 FROM pragma_table_info('keys') WHERE name = 'rpm_limit'").Scan(&hasRPM)
	if errMigrate == nil && !hasRPM {
		_, errMigrate = db.Exec("ALTER TABLE keys ADD COLUMN rpm_limit INTEGER NOT NULL DEFAULT 0")
	}
	if errMigrate != nil {
		_ = db.Close()
		return nil, fmt.Errorf("add rpm_limit: %w", errMigrate)
	}
	return db, nil
}

// close releases the database, also when the host quiesces the plugin before loading another copy of
// it: two copies of SQLite in one process must not hold the same file. A register reopens it.
func (s *keyStore) close() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.closeLocked()
}

func (s *keyStore) closeLocked() {
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
}

// readKeys loads every key with its usage by model, its hours within hourRetention and its recent requests.
func readKeys(db *sql.DB, now time.Time) (map[string]*keyEntry, error) {
	keys := map[string]*keyEntry{}
	errKeys := each(db, "SELECT "+keyColumns+", last_used, "+counterColumns+" FROM keys", func(rows *sql.Rows) error {
		var id, models string
		e := &keyEntry{}
		if errScan := rows.Scan(append([]any{&id, &e.Masked, &e.Name, &e.CreatedAt, &e.ExpiresAt, &e.TokenLimit, &e.RPMLimit, &models, &e.LastUsed}, e.Usage.fields()...)...); errScan != nil {
			return errScan
		}
		keys[id] = e
		if models == "" {
			return nil
		}
		return json.Unmarshal([]byte(models), &e.AllowedModels)
	})
	if errKeys != nil {
		return nil, errKeys
	}
	errModels := each(db, "SELECT scope, model, "+counterColumns+" FROM key_models", func(rows *sql.Rows) error {
		var id, model string
		var c counters
		if errScan := rows.Scan(append([]any{&id, &model}, c.fields()...)...); errScan != nil {
			return errScan
		}
		if e := keys[id]; e != nil {
			e.Models = addTo(e.Models, model, c)
		}
		return nil
	})
	if errModels != nil {
		return nil, errModels
	}
	errHours := each(db, "SELECT scope, hour, "+counterColumns+" FROM key_hours WHERE hour > ?", func(rows *sql.Rows) error {
		var id string
		var hour int64
		var c counters
		if errScan := rows.Scan(append([]any{&id, &hour}, c.fields()...)...); errScan != nil {
			return errScan
		}
		if e := keys[id]; e != nil {
			e.Hours = addTo(e.Hours, hour, c)
		}
		return nil
	}, now.Unix()/3600-hourRetention)
	if errHours != nil {
		return nil, errHours
	}
	errRecent := each(db, "SELECT scope, "+recentColumns+" FROM key_recent ORDER BY rowid", func(rows *sql.Rows) error {
		var id string
		var rr recentRequest
		if errScan := rows.Scan(append([]any{&id}, rr.fields()...)...); errScan != nil {
			return errScan
		}
		if e := keys[id]; e != nil {
			e.Recent = append(e.Recent, rr)
		}
		return nil
	})
	if errRecent != nil {
		return nil, errRecent
	}
	return keys, nil
}

// each calls scan for every row a query returns.
func each(db *sql.DB, query string, scan func(*sql.Rows) error, args ...any) error {
	rows, errQuery := db.Query(query, args...)
	if errQuery != nil {
		return errQuery
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if errScan := scan(rows); errScan != nil {
			return errScan
		}
	}
	return rows.Err()
}

// importJSON moves the data file of versions before 0.4.0 into the database; keys the database already
// has keep their data. The file is renamed before the import commits, so it is imported once.
func importJSON(db *sql.DB, path string) error {
	raw, errRead := os.ReadFile(path)
	if errors.Is(errRead, os.ErrNotExist) {
		return nil
	}
	if errRead != nil {
		return errRead
	}
	var f storeFile
	if errDecode := json.Unmarshal(raw, &f); errDecode != nil {
		return fmt.Errorf("import %s: %w", path, errDecode)
	}
	tx, errBegin := db.Begin()
	if errBegin != nil {
		return errBegin
	}
	defer func() { _ = tx.Rollback() }()
	imported := 0
	for id, e := range f.Keys {
		if e == nil {
			continue
		}
		res, errKey := insert(tx, "keys", keyColumns+", last_used, "+counterColumns, "ON CONFLICT (scope) DO NOTHING",
			append([]any{id, e.Masked, e.Name, e.CreatedAt, e.ExpiresAt, e.TokenLimit, e.RPMLimit, encodeModels(e.AllowedModels), e.LastUsed}, e.Usage.fields()...)...)
		if errKey != nil {
			return errKey
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // the database already has this key
		}
		imported++
		for model, c := range e.Models {
			if c != nil {
				if errModel := addCount(tx, "key_models", "model", id, model, *c); errModel != nil {
					return errModel
				}
			}
		}
		for hour, c := range e.Hours {
			if c != nil {
				if errHour := addCount(tx, "key_hours", "hour", id, hour, *c); errHour != nil {
					return errHour
				}
			}
		}
		for _, rr := range e.Recent {
			if _, errRecent := insert(tx, "key_recent", "scope, "+recentColumns, "", append([]any{id}, rr.fields()...)...); errRecent != nil {
				return errRecent
			}
		}
	}
	done := path + ".imported"
	if errRename := os.Rename(path, done); errRename != nil {
		return errRename
	}
	if errCommit := tx.Commit(); errCommit != nil {
		_ = os.Rename(done, path) // import it again next start
		return errCommit
	}
	hostLog("info", fmt.Sprintf("apikeys: imported %d keys from %s (kept as %s)", imported, path, done))
	return nil
}

// write applies a change to the database in one transaction. Callers hold s.writeMu.
func (s *keyStore) write(change func(*sql.Tx) error) error {
	if s.db == nil {
		return nil // see commit
	}
	tx, errBegin := s.db.Begin()
	if errBegin != nil {
		return errBegin
	}
	if errChange := change(tx); errChange != nil {
		_ = tx.Rollback()
		return errChange
	}
	return tx.Commit()
}

// commit writes a key change at once and reports one that could only be applied in memory.
func (s *keyStore) commit(change func(*sql.Tx) error) error {
	switch {
	case s.openErr != nil:
		return fmt.Errorf("applied until restart, not saved: %w", s.openErr)
	case s.db == nil && s.path != "":
		return errors.New("applied until restart, not saved: the database is closed")
	}
	if errWrite := s.write(change); errWrite != nil {
		return fmt.Errorf("save to %s: %w", s.path, errWrite)
	}
	return nil
}

// insert adds a row of values to table, with an optional conflict clause.
func insert(tx *sql.Tx, table, columns, conflict string, values ...any) (sql.Result, error) {
	return tx.Exec("INSERT INTO "+table+" ("+columns+") VALUES (?"+strings.Repeat(", ?", len(values)-1)+") "+conflict, values...)
}

// addCount adds counters to a key's row in key_models or key_hours.
func addCount(tx *sql.Tx, table, column, id string, value any, c counters) error {
	_, errInsert := insert(tx, table, "scope, "+column+", "+counterColumns, "ON CONFLICT (scope, "+column+") DO UPDATE SET "+addCounters,
		append([]any{id, value}, c.fields()...)...)
	return errInsert
}

// addUsage adds one request to a key's totals, its model and its hour, and to its recent requests,
// of which the newest recentLimit are kept.
func addUsage(tx *sql.Tx, id string, e *keyEntry, hour int64, c counters, rr recentRequest) error {
	if _, errKey := insert(tx, "keys", "scope, masked, created_at, last_used, "+counterColumns,
		"ON CONFLICT (scope) DO UPDATE SET last_used = max(last_used, excluded.last_used), "+addCounters,
		append([]any{id, e.Masked, e.CreatedAt, rr.TS}, c.fields()...)...); errKey != nil {
		return errKey
	}
	if errModel := addCount(tx, "key_models", "model", id, rr.Model, c); errModel != nil {
		return errModel
	}
	if errHour := addCount(tx, "key_hours", "hour", id, hour, c); errHour != nil {
		return errHour
	}
	if _, errRecent := insert(tx, "key_recent", "scope, "+recentColumns, "", append([]any{id}, rr.fields()...)...); errRecent != nil {
		return errRecent
	}
	_, errTrim := tx.Exec("DELETE FROM key_recent WHERE scope = ? AND rowid NOT IN (SELECT rowid FROM key_recent WHERE scope = ? ORDER BY rowid DESC LIMIT ?)", id, id, recentLimit)
	return errTrim
}

// execEach runs each statement with the key's caller scope as its only argument.
func execEach(tx *sql.Tx, id string, statements ...string) error {
	for _, statement := range statements {
		if _, errExec := tx.Exec(statement, id); errExec != nil {
			return errExec
		}
	}
	return nil
}

func encodeModels(models []string) string {
	if len(models) == 0 {
		return ""
	}
	raw, _ := json.Marshal(models)
	return string(raw)
}

// rejection returns the HTTP status and body that refuse a request for the client-requested and the
// resolved model, or 0 when it may proceed. Keys without an entry are unlimited.
func (s *keyStore) rejection(scope, requested, model string, now time.Time) (int, []byte) {
	if scope == "" {
		return 0, nil
	}
	var code, message string
	s.mu.RLock()
	if e := s.keys[scope]; e != nil {
		switch e.status(now) {
		case statusExpired:
			code, message = "api_key_expired", "This API key expired on "+time.UnixMilli(e.ExpiresAt).UTC().Format("2006-01-02 15:04 UTC")+"."
		case statusQuota:
			code, message = "token_quota_exceeded", fmt.Sprintf("This API key has used its token limit (%d of %d tokens).", e.Usage.Input+e.Usage.Output, e.TokenLimit)
		default:
			if !modelAllowed(e.AllowedModels, requested, model) {
				code, message = "model_not_allowed", fmt.Sprintf("This API key may not use model %q.", firstNonEmpty(requested, model, "unknown"))
			}
		}
	}
	s.mu.RUnlock()
	if code == "" {
		return 0, nil
	}
	// 403, not 429: a retry cannot succeed.
	return http.StatusForbidden, errorBody("permission_error", code, message)
}

// throttle admits a request under its key's RPM limit: at most RPMLimit requests in any rpmWindow. A
// refused request takes no slot; it returns the seconds until one frees up and the body that refuses it.
func (s *keyStore) throttle(scope string, now time.Time) (int64, []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.keys[scope]
	if e == nil || e.RPMLimit <= 0 {
		return 0, nil
	}
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	ms := now.UnixMilli()
	i := 0
	for i < len(e.admitted) && e.admitted[i] <= ms-rpmWindow {
		i++
	}
	e.admitted = e.admitted[i:]
	if n := int64(len(e.admitted)); n >= e.RPMLimit {
		// The request fits once all but RPMLimit-1 of the admitted ones have left the window.
		wait := e.admitted[n-e.RPMLimit] + rpmWindow - ms
		retry := (wait + 999) / 1000
		return retry, errorBody("rate_limit_error", "rate_limit_exceeded",
			fmt.Sprintf("This API key is limited to %d requests per minute. Retry in %d s.", e.RPMLimit, retry))
	}
	e.admitted = append(e.admitted, ms)
	return 0, nil
}

// errorBody is one error body that Anthropic- and OpenAI-style clients both read.
func errorBody(typ, code, message string) []byte {
	body, _ := json.Marshal(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": typ, "code": code, "message": message},
	})
	return body
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
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
	s.mu.Unlock()
	// Only writers change entries and they hold writeMu, so e is read here without mu.
	if errWrite := s.write(func(tx *sql.Tx) error { return addUsage(tx, id, e, hour, c, rr) }); errWrite != nil {
		hostLog("warn", "apikeys: save usage: "+errWrite.Error())
	}
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

// modelAllowed reports whether a key limited to patterns may run the client-requested or the resolved
// model; either may match, so aliases work. An empty list allows every model.
func modelAllowed(patterns []string, models ...string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, m := range models {
		m = strings.ToLower(strings.TrimSpace(m))
		if i := strings.IndexByte(m, '('); i > 0 && strings.HasSuffix(m, ")") {
			m = m[:i] // thinking suffix, e.g. gemini-2.5-pro(8192)
		}
		if m != "" && matchAny(patterns, m) {
			return true
		}
	}
	return false
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if matchPattern(p, s) {
			return true
		}
	}
	return false
}

// matchPattern reports whether s matches pattern, where * matches any run of characters, slashes
// included (path.Match stops at "/", which model names such as vendor/model contain).
func matchPattern(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// save creates or updates the limits of a key; its usage is kept.
func (s *keyStore) save(id, masked, name string, expiresAt, tokenLimit, rpmLimit int64, models []string, now time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	e := s.keys[id]
	if e == nil {
		e = &keyEntry{CreatedAt: now.UnixMilli()}
		s.keys[id] = e
	}
	if masked != "" {
		e.Masked = masked
	}
	e.Name, e.ExpiresAt, e.TokenLimit, e.RPMLimit, e.AllowedModels = name, expiresAt, tokenLimit, rpmLimit, models
	s.mu.Unlock()
	return s.commit(func(tx *sql.Tx) error {
		_, errSave := insert(tx, "keys", keyColumns, "ON CONFLICT (scope) DO UPDATE SET masked = excluded.masked, name = excluded.name, "+
			"expires_at = excluded.expires_at, token_limit = excluded.token_limit, rpm_limit = excluded.rpm_limit, allowed_models = excluded.allowed_models",
			id, e.Masked, e.Name, e.CreatedAt, e.ExpiresAt, e.TokenLimit, e.RPMLimit, encodeModels(e.AllowedModels))
		return errSave
	})
}

func (s *keyStore) remove(id string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	delete(s.keys, id)
	s.mu.Unlock()
	return s.commit(func(tx *sql.Tx) error {
		return execEach(tx, id, "DELETE FROM keys WHERE scope = ?", "DELETE FROM key_models WHERE scope = ?",
			"DELETE FROM key_hours WHERE scope = ?", "DELETE FROM key_recent WHERE scope = ?")
	})
}

// resetUsage zeroes what the token limit counts, along with the key's history.
func (s *keyStore) resetUsage(id string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if e := s.keys[id]; e != nil {
		e.Usage, e.LastUsed, e.Models, e.Hours, e.Recent = counters{}, 0, nil, nil, nil
	}
	s.mu.Unlock()
	return s.commit(func(tx *sql.Tx) error {
		return execEach(tx, id, "UPDATE keys SET last_used = 0, requests = 0, failed = 0, input = 0, output = 0, cached = 0, reasoning = 0 WHERE scope = ?",
			"DELETE FROM key_models WHERE scope = ?", "DELETE FROM key_hours WHERE scope = ?", "DELETE FROM key_recent WHERE scope = ?")
	})
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
