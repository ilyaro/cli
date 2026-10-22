# 1Password credential storage (fork feature)

This fork can keep GitHub CLI credentials only in 1Password instead of the
macOS keychain. It is macOS-only and requires the [1Password CLI](https://developer.1password.com/docs/cli/)
(`op`), signed in to your account.

## Usage

```sh
gh auth login --op --expiring
```

- The token (and refresh token, for expiring tokens) is saved in a gh-managed
  item in your account's built-in default vault. No logout or migration is needed.
- A successful `--op` login also runs `gh config set onepassword enabled`, so later
  logins use 1Password without the flag. Stop that with
  `gh config set onepassword disabled`. This affects future logins only.
- Accounts saved in 1Password stay there across `gh auth refresh`, re-login and
  token refresh. Only non-secret item references are written to `hosts.yml`.
- gh calls `op` on every credential lookup and keeps no copy of the token. `op`
  manages its own session and timeout.
- There is no fallback: if `op` is missing, locked, or the item is gone, commands
  fail with an error that names the cause. Run `gh auth login --op` to recover.
- `gh auth logout` deletes the item. `gh auth status` shows the source as `1password`.
- Git over HTTPS works when gh is the credential helper (`gh auth setup-git`, or
  accept the prompt during login). In 1Password mode gh never hands the token to
  another helper.

## Limits

- One item per account per Mac; 1Password sync is not a lock for refresh tokens.
- Existing keychain or plain-text credentials are never read, changed or removed.
- `--op` cannot be combined with `--insecure-storage`.
- Unpatched `gh` and go-gh based extensions cannot read this storage. Use
  `gh auth token` as the bridge.
- Git SSH is out of scope.
- Deleted items follow 1Password retention (Recently Deleted).

## Merging upstream

The feature is isolated in `internal/onepassword/`, `internal/config/onepassword.go`
and their tests. Small hooks live in `internal/config/{config,refreshable}.go`,
`internal/gh/gh.go`, `api/http_client.go`, and `pkg/cmd/auth/{login,refresh,token,gitcredential,shared}`.
`internal/keyring` is untouched. After a merge, re-check those hooks and run
`go test ./internal/... ./pkg/cmd/auth/... ./api/...`.
