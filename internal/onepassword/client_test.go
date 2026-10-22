package onepassword

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeRunner struct {
	stdout, stderr string
	err            error
	gotArgs        []string
	gotStdin       string
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, args ...string) ([]byte, []byte, error) {
	f.gotArgs = args
	f.gotStdin = string(stdin)
	return []byte(f.stdout), []byte(f.stderr), f.err
}

func TestCreateSendsSecretsOnStdinOnly(t *testing.T) {
	r := &fakeRunner{stdout: `{"id":"item1","vault":{"id":"vault1"}}`}
	ref, err := NewClientWithRunner(r).Create(context.Background(), "acct", "gh", Secret{AccessToken: "tok-secret", RefreshToken: "ref-secret"})
	require.NoError(t, err)
	require.Equal(t, Ref{AccountID: "acct", VaultID: "vault1", ItemID: "item1"}, ref)
	require.NotContains(t, r.gotArgs, "tok-secret")
	require.NotContains(t, r.gotArgs, "--vault")
	require.Contains(t, r.gotStdin, "tok-secret")
	require.Contains(t, r.gotStdin, "ref-secret")
}

func TestGet(t *testing.T) {
	ref := Ref{AccountID: "acct", VaultID: "vault1", ItemID: "item1"}
	body := `{"id":"item1","vault":{"id":"vault1"},"fields":[{"label":"access_token","value":"a"},{"label":"refresh_token","value":"r"},{"label":"metadata","value":"{}"}]}`

	t.Run("reads secret", func(t *testing.T) {
		s, err := NewClientWithRunner(&fakeRunner{stdout: body}).Get(context.Background(), ref)
		require.NoError(t, err)
		require.Equal(t, Secret{AccessToken: "a", RefreshToken: "r", Metadata: "{}"}, s)
	})

	t.Run("rejects a different item", func(t *testing.T) {
		_, err := NewClientWithRunner(&fakeRunner{stdout: body}).Get(context.Background(), Ref{AccountID: "acct", VaultID: "vault1", ItemID: "other"})
		require.ErrorIs(t, err, ErrMalformed)
	})

	t.Run("rejects missing access token", func(t *testing.T) {
		_, err := NewClientWithRunner(&fakeRunner{stdout: `{"id":"item1","vault":{"id":"vault1"},"fields":[]}`}).Get(context.Background(), ref)
		require.ErrorIs(t, err, ErrMalformed)
	})

	t.Run("classifies errors", func(t *testing.T) {
		_, err := NewClientWithRunner(&fakeRunner{err: errors.New("exit 1"), stderr: `"item1" isn't an item`}).Get(context.Background(), ref)
		require.ErrorIs(t, err, ErrNotFound)
		_, err = NewClientWithRunner(&fakeRunner{err: errors.New("exit 1"), stderr: "[ERROR] account is not currently signed in"}).Get(context.Background(), ref)
		require.ErrorIs(t, err, ErrUnavailable)
	})
}

func TestDeleteIgnoresMissingItem(t *testing.T) {
	ref := Ref{AccountID: "acct", VaultID: "vault1", ItemID: "item1"}
	require.NoError(t, NewClientWithRunner(&fakeRunner{err: errors.New("exit 1"), stderr: `"item1" isn't an item`}).Delete(context.Background(), ref))
}

func TestPreflight(t *testing.T) {
	id, err := NewClientWithRunner(&fakeRunner{stdout: `{"account_uuid":"acct"}`}).Preflight(context.Background())
	require.NoError(t, err)
	require.Equal(t, "acct", id)
	_, err = NewClientWithRunner(&fakeRunner{stdout: `{}`}).Preflight(context.Background())
	require.ErrorIs(t, err, ErrMalformed)
}
