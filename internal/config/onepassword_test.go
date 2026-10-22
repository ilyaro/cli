package config

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/keyring"
	"github.com/cli/cli/v2/internal/onepassword"
	"github.com/stretchr/testify/require"
)

// fakeOP is an in-memory stand-in for the op CLI holding a single item.
type fakeOP struct {
	item   *itemJSON
	calls  [][]string
	failOn string
	title  string
}

type itemJSON struct {
	ID     string `json:"id"`
	Vault  vault  `json:"vault"`
	Fields []field
}

type vault struct {
	ID string `json:"id"`
}

type field struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func (f *fakeOP) Run(_ context.Context, stdin []byte, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, args)
	if f.failOn != "" && args[0]+" "+args[1] == f.failOn || f.failOn == "whoami --format" && args[0] == "account" {
		return nil, []byte("[ERROR] account is not signed in"), errors.New("exit 1")
	}
	switch args[0] + " " + args[1] {
	case "whoami --format":
		return []byte(`{"account_uuid":"acct1"}`), nil, nil
	case "item create", "item edit":
		var doc struct {
			Title  string  `json:"title"`
			Fields []field `json:"fields"`
		}
		if err := json.Unmarshal(stdin, &doc); err != nil {
			return nil, nil, err
		}
		if f.item == nil {
			f.item = &itemJSON{ID: "item1", Vault: vault{ID: "vault1"}}
		}
		f.item.Fields = doc.Fields
		if args[1] == "create" {
			f.title = doc.Title
		}
	case "item delete":
		f.item = nil
		return nil, nil, nil
	case "item get":
		if f.item == nil {
			return nil, []byte(`"item1" isn't an item`), errors.New("exit 1")
		}
	}
	out, _ := json.Marshal(map[string]any{"id": f.item.ID, "vault": f.item.Vault, "fields": f.item.Fields})
	return out, nil, nil
}

func newOPAuthConfig(t *testing.T) (*AuthConfig, *fakeOP) {
	authCfg := newTestAuthConfig(t)
	fake := &fakeOP{}
	authCfg.op.client = onepassword.NewClientWithRunner(fake)
	return authCfg, fake
}

func TestOnePasswordLoginStoresOnlyInOnePassword(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	require.NoError(t, keyring.Set(keyringServiceName("github.com"), "monalisa", "old-keychain-token"))

	authCfg.UseOnePassword()
	insecure, err := authCfg.Login("github.com", "monalisa", "new-token", "https", false)
	require.NoError(t, err)
	require.False(t, insecure)

	cred := authCfg.ActiveToken("github.com")
	require.Equal(t, "new-token", cred.Token)
	require.Equal(t, gh.TokenSourceOnePassword, cred.Source)
	require.True(t, authCfg.OnePasswordUser("github.com", "monalisa"))
	require.Equal(t, "ghcli_monalisa_github.com", fake.title)

	// The keychain entry is neither read as the credential nor modified.
	old, err := keyring.Get(keyringServiceName("github.com"), "monalisa")
	require.NoError(t, err)
	require.Equal(t, "old-keychain-token", old)

	// Nothing secret reaches the op command line or hosts.yml.
	for _, call := range fake.calls {
		require.NotContains(t, call, "new-token")
	}
	_, err = authCfg.cfg.Get([]string{hostsKey, "github.com", "oauth_token"})
	require.Error(t, err)
}

func TestOnePasswordLoginUpdatesExistingItem(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	authCfg.UseOnePassword()
	_, err := authCfg.Login("github.com", "monalisa", "first", "https", false)
	require.NoError(t, err)
	_, err = authCfg.Login("github.com", "monalisa", "second", "https", false)
	require.NoError(t, err)

	creates := 0
	for _, call := range fake.calls {
		if call[0] == "item" && call[1] == "create" {
			creates++
		}
	}
	require.Equal(t, 1, creates)
	require.Equal(t, "second", authCfg.ActiveToken("github.com").Token)
}

func TestOnePasswordReadFailureDoesNotFallBack(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	authCfg.UseOnePassword()
	_, err := authCfg.Login("github.com", "monalisa", "tok", "https", false)
	require.NoError(t, err)
	require.NoError(t, keyring.Set(keyringServiceName("github.com"), "monalisa", "stale"))

	fake.failOn = "item get"
	require.Empty(t, authCfg.ActiveToken("github.com").Token)
	_, err = authCfg.TokenForUser("github.com", "monalisa")
	require.ErrorIs(t, err, onepassword.ErrUnavailable)
}

func TestOnePasswordLoginFailureLeavesNoState(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	fake.failOn = "whoami --format"
	authCfg.UseOnePassword()
	_, err := authCfg.Login("github.com", "monalisa", "tok", "https", false)
	require.ErrorIs(t, err, onepassword.ErrUnavailable)
	require.False(t, authCfg.OnePasswordUser("github.com", "monalisa"))
}

func TestOnePasswordLogoutDeletesItem(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	authCfg.UseOnePassword()
	_, err := authCfg.Login("github.com", "monalisa", "tok", "https", false)
	require.NoError(t, err)

	require.NoError(t, authCfg.Logout("github.com", "monalisa"))
	require.Nil(t, fake.item)
	require.False(t, authCfg.OnePasswordUser("github.com", "monalisa"))
}

func TestOnePasswordLogoutKeepsReferenceWhenDeleteFails(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	authCfg.UseOnePassword()
	_, err := authCfg.Login("github.com", "monalisa", "tok", "https", false)
	require.NoError(t, err)

	fake.failOn = "item delete"
	require.Error(t, authCfg.Logout("github.com", "monalisa"))
	require.True(t, authCfg.OnePasswordUser("github.com", "monalisa"))
}

func TestOnePasswordNotUsedForOtherAccounts(t *testing.T) {
	authCfg, fake := newOPAuthConfig(t)
	require.NoError(t, keyring.Set(keyringServiceName("github.com"), "hubot", "keychain-token"))
	_, err := authCfg.Login("github.com", "hubot", "keychain-token", "https", false)
	require.NoError(t, err)

	require.Equal(t, "keychain-token", authCfg.ActiveToken("github.com").Token)
	require.Empty(t, fake.calls)
}

func TestOnePasswordDefaultOption(t *testing.T) {
	cfg, _ := NewIsolatedTestConfig(t, "")
	require.False(t, OnePasswordEnabled(cfg))
	require.NoError(t, EnableOnePasswordByDefault(cfg))
	require.True(t, OnePasswordEnabled(cfg))
}
