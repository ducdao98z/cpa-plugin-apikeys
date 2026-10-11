# API Key Manager plugin for CLIProxyAPI

Manage the client API keys of [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (`access.api-keys`, the
panel's Client API Keys) with expiry dates, token limits, requests-per-minute limits and the models each key may
use, and see what each key used.

- **Keys:** add (generated like the panel's Generate), rename, set limits, delete. Keys are written to the core
  config through the Management API, so the panel and this page always show the same list.
- **Expiry:** never, 7/30/90 days or a date. Afterwards, model requests with the key get HTTP 403
  (`api_key_expired`).
- **Token limit:** input + output tokens (cached input included). Once used, model requests get HTTP 403
  (`token_quota_exceeded`) until the limit is raised or the usage is reset. The check runs before each request,
  so requests already running can overshoot it.
- **Requests per minute:** at most N model requests in any 60 seconds (a sliding window). More get HTTP 429
  (`rate_limit_exceeded`) with `Retry-After`; refused requests take no slot. Requests count when they start, whether
  they succeed or not. `/v1/messages/count_tokens` is not counted (Gemini's `countTokens` shares its route with
  `generateContent`, so it is). The window lives in memory and starts empty after a restart.
- **Models:** an optional allow-list of patterns (`*` matches any text, e.g. `gpt-5*`, `claude-sonnet-*`), matched
  case-insensitively against the requested model or the model its alias resolves to. Other models get HTTP 403
  (`model_not_allowed`).
- **Usage:** per key totals, last 30 days by day, by model, and its requests. With the
  [Usage Analytics](https://github.com/ducdao98z/cpa-plugin-usage) plugin (0.5.0 or later) the requests page
  through its history, matched by masked key; without it, the last 20.
- Follows the panel's theme and reuses its login; key names are shared with the panel (and the
  [Usage Analytics](https://github.com/ducdao98z/cpa-plugin-usage) plugin) in the same browser.

Keys without limits behave exactly as before. Only model requests are checked; `/v1/models` stays open.
Usage is counted from the moment the plugin loads.

Requires CLIProxyAPI v8.0.22 or later with plugins enabled.

## Install

**Manually:** download `apikeys_<version>_<os>_<arch>.zip` from
[Releases](https://github.com/ducdao98z/cpa-plugin-apikeys/releases), extract `apikeys.so` / `.dylib` / `.dll`
into the plugins directory (`plugins/` by default), enable it (below) and restart.

**From source** (Go 1.26+ and a C compiler):

```bash
go build -trimpath -buildvcs=false -buildmode=c-shared -ldflags "-s -w" -o apikeys.so . && rm -f apikeys.h
```

For the official Docker image (Debian bookworm), build in a matching container so glibc fits:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.26-bookworm \
  sh -c 'go build -trimpath -buildvcs=false -buildmode=c-shared -ldflags "-s -w" -o apikeys.so . && rm -f apikeys.h'
```

## Configure

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    apikeys:
      enabled: true
      data-file: "plugins/apikeys.db" # optional, this is the default (relative to the working directory)
```

Versions before 0.4.0 kept everything in `plugins/apikeys.json`. On first start, 0.4.0 imports that file into the
database (keys the database already has keep their data) and keeps it as `apikeys.json.imported`; a `data-file`
that still names the `.json` file means the `.db` next to it.

## Open

**API Key Manager** under PLUGINS in the management panel, or `http://<host>:8317/v0/resource/plugins/apikeys/ui`.

## How it works

- Keys are identified by their caller scope, the SHA-256 that CLIProxyAPI attaches to every request as
  `caller_scope`. The plugin never sees or stores a raw key; its database holds limits, the masked key and usage.
- `request.intercept_before` refuses requests of expired or exhausted keys and models off the list, then admits the
  request under the key's RPM limit; `usage.handle` counts tokens.
- `data-file` is a SQLite database (WAL mode, pure-Go driver, so no C SQLite is needed) with the tables `keys`,
  `key_models`, `key_hours` and `key_recent`. Every change is written at once; the limit check reads a copy in
  memory. The database keeps every hourly bucket, while the page loads the last 31 days.

### Management API

All routes need the management key. `id` is the key's caller scope:
`sha256("cli-proxy-api:caller-scope:v1\x00" + key)` in hex.

| Route | Purpose |
|---|---|
| `GET /v0/management/apikeys` | Limits, usage totals and status of every known key |
| `GET /v0/management/apikeys/detail?id=` | One key with usage by model, by hour (31 days) and recent requests |
| `POST /v0/management/apikeys/save` | `{id, masked, name, expires_at, token_limit, rpm_limit, allowed_models}` (unix ms, tokens, requests per minute, patterns; 0 or empty = none) |
| `POST /v0/management/apikeys/delete` | `{id}`: forget limits and usage |
| `POST /v0/management/apikeys/reset` | `{id}`: zero the usage, restarting the token limit |

## Release

Push a `v<version>` tag. The Build workflow tests, builds linux/darwin/windows libraries, and publishes
`apikeys_<version>_<os>_<arch>.zip` plus `checksums.txt` in the layout the CLIProxyAPI plugin store installs.

## License

MIT. The page's design tokens and component styles follow the
[CLIProxyAPI Management Center](https://github.com/router-for-me/Cli-Proxy-API-Management-Center) (MIT, © Router-For.ME).
