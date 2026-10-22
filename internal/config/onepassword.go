package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/onepassword"
)

// onepasswordKey names two things that share one spelling on purpose:
//   - the global option "onepassword" (enabled/disabled) in config.yml, which makes 1Password the default
//     credential store for FUTURE logins, and
//   - the per-user mapping hosts.<host>.users.<user>.onepassword in hosts.yml, which holds the NON-SECRET
//     reference (account, vault and item IDs) to the user's 1Password item.
//
// No token or refresh token is ever written to hosts.yml, to the system keyring or to any gh-side cache. The only
// place a secret lives is the 1Password item. Session handling (unlock, biometrics, session timeout) belongs
// entirely to the op CLI and the 1Password app, which keep their own authenticated session for a limited time; gh
// simply asks op for the item whenever it needs the token.
const onepasswordKey = "onepassword"

// OnePasswordEnabled reports whether the global onepassword option makes 1Password the default credential store for
// new logins. It only describes the default for future logins: accounts that are already stored in 1Password stay
// there regardless of this value, and accounts stored elsewhere are not migrated.
func OnePasswordEnabled(c gh.Config) bool {
	return c.GetOrDefault("", onepasswordKey).Unwrap().Value == "enabled"
}

// EnableOnePasswordByDefault persists the global onepassword option as "enabled" so later logins use 1Password
// without passing --op. It is called after a successful explicit 1Password login.
func EnableOnePasswordByDefault(c gh.Config) error {
	c.Set("", onepasswordKey, "enabled")
	return c.Write()
}

// opState holds the 1Password related state of an AuthConfig. The zero value is ready to use. It deliberately
// contains no credential: gh keeps no copy of any token, and relies on op's own session for speed.
type opState struct {
	// client talks to the op CLI. It is created lazily, and tests replace it with one backed by a fake runner.
	client *onepassword.Client
	// login routes Login and LoginRefreshable to 1Password for the rest of this process. The shared login flow
	// calls those methods through interfaces that have no storage argument, so this flag carries the choice.
	login bool
}

// opPath is the hosts.yml location of the user's non-secret 1Password item reference.
func opPath(hostname, username string) []string {
	return []string{hostsKey, hostname, usersKey, username, onepasswordKey}
}

// opClient returns the op CLI client, creating the real one on first use.
func (c *AuthConfig) opClient() *onepassword.Client {
	if c.op.client == nil {
		c.op.client = onepassword.NewClient()
	}
	return c.op.client
}

// UseOnePassword routes this process's subsequent Login and LoginRefreshable calls to 1Password instead of the
// keyring or plain text config. It is a one-way switch for the lifetime of the process because every gh command is
// a short-lived process.
func (c *AuthConfig) UseOnePassword() { c.op.login = true }

// OnePasswordUser reports whether the user's credential is stored in 1Password.
func (c *AuthConfig) OnePasswordUser(hostname, username string) bool {
	_, ok := c.opRef(hostname, username)
	return ok
}

// opRef reads the user's 1Password item reference from hosts.yml. It reports false when the user is not stored in
// 1Password or when the reference is incomplete, in which case callers fall back to the other credential stores.
func (c *AuthConfig) opRef(hostname, username string) (onepassword.Ref, bool) {
	if username == "" {
		return onepassword.Ref{}, false
	}
	path := opPath(hostname, username)
	var ref onepassword.Ref
	var err error
	if ref.AccountID, err = c.cfg.Get(append(path, "account_id")); err != nil {
		return ref, false
	}
	if ref.VaultID, err = c.cfg.Get(append(path, "vault_id")); err != nil {
		return ref, false
	}
	if ref.ItemID, err = c.cfg.Get(append(path, "item_id")); err != nil {
		return ref, false
	}
	return ref, ref.Valid()
}

// setOPRef records the user's 1Password item reference in the in-memory config. The caller writes the config.
func (c *AuthConfig) setOPRef(hostname, username string, ref onepassword.Ref) {
	path := opPath(hostname, username)
	c.cfg.Set(append(path, "account_id"), ref.AccountID)
	c.cfg.Set(append(path, "vault_id"), ref.VaultID)
	c.cfg.Set(append(path, "item_id"), ref.ItemID)
}

// clearOPRef removes the user's 1Password item reference from the in-memory config. The caller writes the config.
func (c *AuthConfig) clearOPRef(hostname, username string) {
	_ = c.cfg.Remove(opPath(hostname, username))
}

// opSecret splits a credential into the payload stored in the 1Password item. The tokens go into the concealed
// fields; Metadata carries only expiry information (never a token), reusing the refreshable record JSON shape.
func opSecret(credential gh.Credential) (onepassword.Secret, error) {
	record := recordFromCredential(credential)
	record.AccessToken, record.RefreshToken = "", ""
	meta, err := json.Marshal(normalizeToUTC(record))
	if err != nil {
		return onepassword.Secret{}, errors.New("could not encode credential metadata")
	}
	return onepassword.Secret{
		AccessToken:  credential.Token,
		RefreshToken: credential.RefreshToken,
		Metadata:     string(meta),
	}, nil
}

// opCredential rebuilds a credential from the item payload and tags it with the 1password token source. A credential
// that carries a refresh token must also be a valid refreshable credential; one without is a plain non-expiring token.
func opCredential(secret onepassword.Secret) (gh.Credential, error) {
	var record refreshableTokenRecord
	if secret.Metadata != "" {
		if err := json.Unmarshal([]byte(secret.Metadata), &record); err != nil {
			return gh.Credential{}, fmt.Errorf("%w: invalid metadata", onepassword.ErrMalformed)
		}
	}
	record.AccessToken, record.RefreshToken = secret.AccessToken, secret.RefreshToken
	credential := record.credential(gh.TokenSourceOnePassword)
	if credential.RefreshToken != "" {
		return credential, validateRefreshableCredential(credential)
	}
	return credential, nil
}

// readOP reads the user's credential from 1Password through op. A failure returns an empty credential and an
// explicit error, so callers never fall back to another store or send a request with a stale token.
func (c *AuthConfig) readOP(hostname, username string, ref onepassword.Ref) (gh.Credential, error) {
	secret, err := c.opClient().Get(context.Background(), ref)
	if err == nil {
		var credential gh.Credential
		if credential, err = opCredential(secret); err == nil {
			return credential, nil
		}
	}
	hint := ""
	if errors.Is(err, onepassword.ErrNotFound) {
		hint = "; run 'gh auth login --op' to authenticate again"
	}
	return gh.Credential{Source: gh.TokenSourceOnePassword}, fmt.Errorf("could not read the 1Password credential for %s on %s: %w%s", username, hostname, err, hint)
}

// writeOP overwrites the secret in the user's existing 1Password item, for example with a rotated refresh token.
func (c *AuthConfig) writeOP(ref onepassword.Ref, credential gh.Credential) error {
	secret, err := opSecret(credential)
	if err != nil {
		return err
	}
	return c.opClient().Update(context.Background(), ref, secret)
}

// loginOnePassword stores the credential in 1Password, records the item reference in hosts.yml and activates the
// user. It never reads, writes or deletes anything in the system keyring, so an existing keyring credential for the
// same account is left untouched. If the user already has an item it is updated in place; otherwise a new item is
// created in the account's built-in default vault. If activation fails after a new item was created, that item is
// deleted again so a failed login does not leave an orphaned secret.
func (c *AuthConfig) loginOnePassword(hostname, username string, credential gh.Credential, gitProtocol string) error {
	if hostname == "" || username == "" {
		return errors.New("hostname and username are required")
	}
	ctx := context.Background()
	client := c.opClient()

	secret, err := opSecret(credential)
	if err != nil {
		return err
	}

	ref, existing := c.opRef(hostname, username)
	if existing {
		if err := client.Update(ctx, ref, secret); errors.Is(err, onepassword.ErrNotFound) {
			// The item was deleted outside gh, so fall through and create a fresh one.
			existing = false
		} else if err != nil {
			return err
		}
	}
	if !existing {
		accountID, err := client.Preflight(ctx)
		if err != nil {
			return err
		}
		title := fmt.Sprintf("ghcli_%s_%s", username, hostname)
		if ref, err = client.Create(ctx, accountID, title, secret); err != nil {
			return err
		}
	}

	c.setOPRef(hostname, username, ref)
	if err := c.completeLogin(hostname, username, gitProtocol); err != nil {
		if !existing {
			_ = client.Delete(ctx, ref)
			c.clearOPRef(hostname, username)
		}
		return err
	}
	return nil
}

// forgetOnePassword drops the 1Password registration of a user who is now logging in through another store, so the
// stale reference cannot shadow the new credential. The no longer used item is deleted on a best effort basis.
func (c *AuthConfig) forgetOnePassword(hostname, username string) {
	if ref, ok := c.opRef(hostname, username); ok {
		_ = c.opClient().Delete(context.Background(), ref)
		c.clearOPRef(hostname, username)
	}
}

// deleteOnePasswordItem removes the user's 1Password item during logout and reports whether the user was stored in
// 1Password. A failure is returned so logout does not report success while the secret still exists.
func (c *AuthConfig) deleteOnePasswordItem(hostname, username string) (bool, error) {
	ref, ok := c.opRef(hostname, username)
	if !ok {
		return false, nil
	}
	if err := c.opClient().Delete(context.Background(), ref); err != nil {
		return true, fmt.Errorf("could not remove the 1Password item for %s on %s: %w", username, hostname, err)
	}
	return true, nil
}
