package login

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/google/shlex"
	"github.com/stretchr/testify/require"
)

func TestNewCmdLogin_onePasswordFlag(t *testing.T) {
	t.Setenv("GH_HOST", "github.com")
	tests := []struct {
		name     string
		cli      string
		wantOP   bool
		wantsErr string
	}{
		{name: "op with expiring", cli: "--op --expiring", wantOP: true},
		{name: "op alone", cli: "--op", wantOP: true},
		{name: "op with insecure storage", cli: "--op --insecure-storage", wantsErr: "--op"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ios, _, _, _ := iostreams.Test()
			argv, err := shlex.Split(tt.cli)
			require.NoError(t, err)

			var got *LoginOptions
			cmd := NewCmdLogin(&cmdutil.Factory{IOStreams: ios}, nil, func(o *LoginOptions) error {
				got = o
				return nil
			})
			cmd.Flags().BoolP("help", "x", false, "")
			cmd.SetArgs(argv)
			cmd.SetIn(&bytes.Buffer{})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})

			_, err = cmd.ExecuteC()
			if tt.wantsErr != "" {
				require.ErrorContains(t, err, tt.wantsErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantOP, got.OnePassword)
		})
	}
}

func TestResolveOnePassword(t *testing.T) {
	cfg, _ := config.NewIsolatedTestConfig(t, "")
	preflightErr := errors.New("account is not signed in")

	t.Run("not requested", func(t *testing.T) {
		use, err := resolveOnePassword(&LoginOptions{goos: "darwin", onePasswordPreflight: func() error { t.Fatal("op must not run"); return nil }}, cfg)
		require.NoError(t, err)
		require.False(t, use)
	})
	t.Run("rejects other platforms", func(t *testing.T) {
		_, err := resolveOnePassword(&LoginOptions{OnePassword: true, goos: "linux", onePasswordPreflight: func() error { return nil }}, cfg)
		require.ErrorContains(t, err, "macOS")
	})
	t.Run("preflight failure has no fallback", func(t *testing.T) {
		_, err := resolveOnePassword(&LoginOptions{OnePassword: true, goos: "darwin", onePasswordPreflight: func() error { return preflightErr }}, cfg)
		require.ErrorIs(t, err, preflightErr)
	})
	t.Run("explicit flag", func(t *testing.T) {
		use, err := resolveOnePassword(&LoginOptions{OnePassword: true, goos: "darwin", onePasswordPreflight: func() error { return nil }}, cfg)
		require.NoError(t, err)
		require.True(t, use)
	})
	t.Run("default enabled", func(t *testing.T) {
		require.NoError(t, config.EnableOnePasswordByDefault(cfg))
		use, err := resolveOnePassword(&LoginOptions{goos: "darwin", onePasswordPreflight: func() error { return nil }}, cfg)
		require.NoError(t, err)
		require.True(t, use)
	})
	t.Run("default with insecure storage is skipped", func(t *testing.T) {
		use, err := resolveOnePassword(&LoginOptions{InsecureStorage: true, goos: "darwin"}, cfg)
		require.NoError(t, err)
		require.False(t, use)
	})
}
