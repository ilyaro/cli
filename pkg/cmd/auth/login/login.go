package login

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/v2/git"
	"github.com/cli/cli/v2/internal/authflow"
	"github.com/cli/cli/v2/internal/browser"
	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/gh/ghtelemetry"
	"github.com/cli/cli/v2/internal/ghinstance"
	"github.com/cli/cli/v2/internal/onepassword"
	"github.com/cli/cli/v2/pkg/cmd/auth/shared"
	"github.com/cli/cli/v2/pkg/cmd/auth/shared/gitcredentials"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	ghauth "github.com/cli/go-gh/v2/pkg/auth"
	"github.com/spf13/cobra"
)

type LoginOptions struct {
	IO              *iostreams.IOStreams
	Config          func() (gh.Config, error)
	HttpClient      func() (*http.Client, error)
	PlainHttpClient func() (*http.Client, error)
	GitClient       *git.Client
	Prompter        shared.Prompt
	Browser         browser.Browser
	Telemetry       ghtelemetry.InvocationRecorder

	MainExecutable string

	Interactive bool

	Hostname         string
	Scopes           []string
	Token            string
	Web              bool
	GitProtocol      string
	InsecureStorage  bool
	SkipSSHKeyPrompt bool
	Expiring         *bool
	Clipboard        *bool
	// OnePassword stores the credential in 1Password through the op CLI instead of the system keyring. On success it
	// also makes 1Password the default store for future logins.
	OnePassword bool

	// onePasswordPreflight verifies that op is installed and signed in. It is nil in production; tests replace it.
	onePasswordPreflight func() error
	// goos is the operating system name. It is empty in production, where runtime.GOOS is used.
	goos string

	// AuthFlow is indirected so tests can stub the interactive authorization. When nil, the shared login flow uses
	// the real authflow.AuthFlow.
	AuthFlow func(*http.Client, string, *iostreams.IOStreams, string, []string, bool, browser.Browser, bool, bool) (*authflow.AuthResult, error)

	// helperConfig overrides git credential helper inspection and configuration. It is nil in production, where
	// runLogin builds the real HelperConfig from GitClient; tests set a fake to avoid shelling out to git.
	helperConfig shared.HelperConfig
}

func NewCmdLogin(f *cmdutil.Factory, telemetry ghtelemetry.InvocationRecorder, runF func(*LoginOptions) error) *cobra.Command {
	opts := &LoginOptions{
		IO:              f.IOStreams,
		Config:          f.Config,
		HttpClient:      f.HttpClient,
		PlainHttpClient: f.PlainHttpClient,
		GitClient:       f.GitClient,
		Prompter:        f.Prompter,
		Browser:         f.Browser,
		Telemetry:       telemetry,
	}

	var tokenStdin bool

	cmd := &cobra.Command{
		Use:   "login",
		Args:  cobra.ExactArgs(0),
		Short: "Log in to a GitHub account",
		Long: heredoc.Docf(`
			Authenticate with a GitHub host.

			The default hostname is %[1]sgithub.com%[1]s. This can be overridden using the %[1]s--hostname%[1]s
			flag.

			The default authentication mode is a web-based browser flow. After completion, an
			authentication token will be stored securely in the system credential store.
			If a credential store is not found or there is an issue using it gh will fallback
			to writing the token to a plain text file. See %[1]sgh auth status%[1]s for its
			stored location.

			Alternatively, use %[1]s--with-token%[1]s to pass in a personal access token (classic) on standard input.
			The minimum required scopes for the token are: %[1]srepo%[1]s, %[1]sread:org%[1]s, and %[1]sgist%[1]s.
			Take care when passing a fine-grained personal access token to %[1]s--with-token%[1]s
			as the inherent scoping to certain resources may cause confusing behaviour when interacting with other
			resources. Favour setting %[1]sGH_TOKEN%[1]s for fine-grained personal access token usage.

			Alternatively, gh will use the authentication token found in environment variables.
			This method is most suitable for "headless" use of gh such as in automation. See
			%[1]sgh help environment%[1]s for more info.

			To use gh in GitHub Actions, add %[1]sGH_TOKEN: ${{ github.token }}%[1]s to %[1]senv%[1]s.

			The git protocol to use for git operations on this host can be set with %[1]s--git-protocol%[1]s,
			or during the interactive prompting. Although login is for a single account on a host, setting
			the git protocol will take effect for all users on the host.

			Specifying %[1]sssh%[1]s for the git protocol will detect existing SSH keys to upload,
			prompting to create and upload a new key if one is not found. This can be skipped with
			%[1]s--skip-ssh-key%[1]s flag.

			Use %[1]s--expiring%[1]s to prefer expiring credentials that gh refreshes automatically.
			This is a preference, not a guarantee: whether expiring tokens are issued depends on the
			host and the OAuth app configuration. A host without support issues a non-expiring token
			instead, and a host configured for them may issue expiring tokens even without the flag.
			Enable the %[1]sexpiring_credentials%[1]s configuration to prefer expiring credentials
			without passing %[1]s--expiring%[1]s every time, and pass %[1]s--expiring=false%[1]s to request a
			non-expiring token even when that configuration is enabled.
			When using expiring credentials for git operations, git 2.46 or newer is recommended so
			gh can mark the token as non-cacheable; with older git a credential caching helper may store
			and reuse an expired token.

			Use %[1]s--op%[1]s to keep the token (and refresh token) only in 1Password through the %[1]sop%[1]s CLI
			instead of the system keyring (macOS only). The credential is saved in your default 1Password vault, gh
			reads it from 1Password whenever it needs it, and gh remains the Git credential helper. A successful login
			with %[1]s--op%[1]s makes 1Password the default store for later logins (see the %[1]sonepassword%[1]s
			configuration); run %[1]sgh config set onepassword disabled%[1]s to stop that. Existing keyring
			credentials are left untouched. Combine with %[1]s--expiring%[1]s for refreshable credentials.

			For more information on OAuth scopes, see
			<https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps/>.
		`, "`"),
		Example: heredoc.Doc(`
			# Start interactive setup
			$ gh auth login

			# Open a browser to authenticate and copy one-time OAuth code to clipboard
			$ gh auth login --web --clipboard

			# Authenticate against github.com by reading the token from a file
			$ gh auth login --with-token < mytoken.txt

			# Authenticate with specific host
			$ gh auth login --hostname enterprise.internal
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Telemetry != nil {
				opts.Telemetry.SetSampleRate(ghtelemetry.SAMPLE_ALL)
			}

			if tokenStdin && opts.Web {
				return cmdutil.FlagErrorf("specify only one of `--web` or `--with-token`")
			}
			if tokenStdin && len(opts.Scopes) > 0 {
				return cmdutil.FlagErrorf("specify only one of `--scopes` or `--with-token`")
			}
			if tokenStdin && opts.Expiring != nil && *opts.Expiring {
				return cmdutil.FlagErrorf("specify only one of `--expiring` or `--with-token`")
			}

			if opts.OnePassword && opts.InsecureStorage {
				return cmdutil.FlagErrorf("specify only one of `--op` or `--insecure-storage`")
			}

			if tokenStdin {
				defer opts.IO.In.Close()
				token, err := io.ReadAll(opts.IO.In)
				if err != nil {
					return fmt.Errorf("failed to read token from standard input: %w", err)
				}
				opts.Token = strings.TrimSpace(string(token))
			}

			if opts.IO.CanPrompt() && opts.Token == "" {
				opts.Interactive = true
			}

			if cmd.Flags().Changed("hostname") {
				if err := ghinstance.HostnameValidator(opts.Hostname); err != nil {
					return cmdutil.FlagErrorf("error parsing hostname: %w", err)
				}
			}

			if opts.Hostname == "" && (!opts.Interactive || opts.Web) {
				opts.Hostname, _ = ghauth.DefaultHost()
			}

			opts.MainExecutable = f.ExecutablePath
			if runF != nil {
				return runF(opts)
			}

			return loginRun(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "", "The hostname of the GitHub instance to authenticate with")
	cmd.Flags().StringSliceVarP(&opts.Scopes, "scopes", "s", nil, "Additional authentication scopes to request")
	cmd.Flags().BoolVar(&tokenStdin, "with-token", false, "Read token from standard input")
	cmd.Flags().BoolVarP(&opts.Web, "web", "w", false, "Open a browser to authenticate")
	cmdutil.NilBoolFlag(cmd, &opts.Clipboard, "clipboard", "c", "Copy one-time OAuth device code to clipboard")
	cmdutil.StringEnumFlag(cmd, &opts.GitProtocol, "git-protocol", "p", "", []string{"ssh", "https"}, "The protocol to use for git operations on this host")

	// secure storage became the default on 2023/4/04; this flag is left as a no-op for backwards compatibility
	var secureStorage bool
	cmd.Flags().BoolVar(&secureStorage, "secure-storage", false, "Save authentication credentials in secure credential store")
	_ = cmd.Flags().MarkHidden("secure-storage")

	cmd.Flags().BoolVar(&opts.InsecureStorage, "insecure-storage", false, "Save authentication credentials in plain text instead of credential store")
	cmd.Flags().BoolVar(&opts.SkipSSHKeyPrompt, "skip-ssh-key", false, "Skip generate/upload SSH key prompt")
	cmdutil.NilBoolFlag(cmd, &opts.Expiring, "expiring", "", "Prefer expiring credentials that gh refreshes automatically, if the host supports them")
	cmd.Flags().BoolVar(&opts.OnePassword, "op", false, "Save authentication credentials in 1Password (macOS) and use it by default for future logins")

	return cmd
}

func loginRun(opts *LoginOptions) error {
	cfg, err := opts.Config()
	if err != nil {
		return err
	}
	authCfg := cfg.Authentication()
	// Decide the credential store before any prompt or OAuth step, so a missing op fails early and never falls back.
	useOP, err := resolveOnePassword(opts, cfg)
	if err != nil {
		return err
	}
	if useOP {
		enabler, ok := authCfg.(interface{ UseOnePassword() })
		if !ok {
			return errors.New("1Password storage is not supported by this configuration")
		}
		enabler.UseOnePassword()
	}

	copyToClipboard := shared.ShouldCopyToClipboard(cfg, opts.Clipboard)

	hostname := opts.Hostname
	if opts.Interactive && hostname == "" {
		var err error
		hostname, err = promptForHostname(opts)
		if err != nil {
			return err
		}
	}

	// The go-gh Config object currently does not support case-insensitive lookups for host names,
	// so normalize the host name case here before performing any lookups with it or persisting it.
	// https://github.com/cli/go-gh/pull/105
	hostname = strings.ToLower(hostname)

	if src, writeable := shared.AuthTokenWriteable(authCfg, hostname); !writeable {
		fmt.Fprintf(opts.IO.ErrOut, "The value of the %s environment variable is being used for authentication.\n", src)
		fmt.Fprint(opts.IO.ErrOut, "To have GitHub CLI store credentials instead, first clear the value from the environment.\n")
		return cmdutil.SilentError
	}

	plainHTTPClient, err := opts.PlainHttpClient()
	if err != nil {
		return err
	}

	httpClient, err := opts.HttpClient()
	if err != nil {
		return err
	}

	if opts.Token != "" {
		if err := shared.HasMinimumScopes(httpClient, hostname, opts.Token); err != nil {
			return fmt.Errorf("error validating token: %w", err)
		}
		username, err := shared.GetCurrentLogin(httpClient, hostname, opts.Token)
		if err != nil {
			return fmt.Errorf("error retrieving current user: %w", err)
		}

		// Adding a user key ensures that a nonempty host section gets written to the config file.
		_, loginErr := authCfg.Login(hostname, username, opts.Token, opts.GitProtocol, !opts.InsecureStorage)
		if loginErr != nil {
			return loginErr
		}
		return enableOnePasswordDefault(opts, cfg)
	}

	helperConfig := opts.helperConfig
	if helperConfig == nil {
		helperConfig = &gitcredentials.HelperConfig{
			SelfExecutablePath: opts.MainExecutable,
			GitClient:          opts.GitClient,
		}
	}

	err = shared.Login(&shared.LoginOptions{
		IO:              opts.IO,
		Config:          authCfg,
		HTTPClient:      httpClient,
		PlainHTTPClient: plainHTTPClient,
		Hostname:        hostname,
		Interactive:     opts.Interactive,
		Web:             opts.Web,
		Scopes:          opts.Scopes,
		GitProtocol:     opts.GitProtocol,
		Prompter:        opts.Prompter,
		Browser:         opts.Browser,
		CredentialFlow: &shared.GitCredentialFlow{
			Prompter:     opts.Prompter,
			IO:           opts.IO,
			HelperConfig: helperConfig,
			OnePassword:  useOP,
			Updater: &gitcredentials.Updater{
				GitClient: opts.GitClient,
			},
		},
		SecureStorage:               !opts.InsecureStorage,
		SkipSSHKeyPrompt:            opts.SkipSSHKeyPrompt,
		CopyToClipboard:             copyToClipboard,
		Expiring:                    shared.ShouldUseExpiring(cfg, opts.Expiring, hostname),
		ExpiringExplicitlyRequested: opts.Expiring != nil && *opts.Expiring,
		Telemetry:                   opts.Telemetry,
		AuthFlow:                    opts.AuthFlow,
	})
	if err != nil {
		return err
	}
	return enableOnePasswordDefault(opts, cfg)
}

// resolveOnePassword decides whether this login stores its credential in 1Password: explicitly through --op, or
// because the global onepassword option is enabled and the user did not ask for plain text storage. It fails before
// any login step when 1Password cannot be used, because there is deliberately no fallback to the keyring.
func resolveOnePassword(opts *LoginOptions, cfg gh.Config) (bool, error) {
	if !opts.OnePassword && (opts.InsecureStorage || !config.OnePasswordEnabled(cfg)) {
		return false, nil
	}
	goos := opts.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos != "darwin" {
		return false, errors.New("1Password storage is only supported on macOS")
	}
	preflight := opts.onePasswordPreflight
	if preflight == nil {
		preflight = func() error {
			_, err := onepassword.NewClient().Preflight(context.Background())
			return err
		}
	}
	if err := preflight(); err != nil {
		return false, fmt.Errorf("cannot use 1Password: %w; sign in with the op CLI and try again", err)
	}
	return true, nil
}

// enableOnePasswordDefault makes 1Password the default store for future logins after a successful explicit --op login.
// The credential is already saved, so a failure here is reported as a partial success.
func enableOnePasswordDefault(opts *LoginOptions, cfg gh.Config) error {
	if !opts.OnePassword || config.OnePasswordEnabled(cfg) {
		return nil
	}
	if err := config.EnableOnePasswordByDefault(cfg); err != nil {
		return fmt.Errorf("logged in with 1Password, but could not make it the default: %w; run 'gh config set onepassword enabled'", err)
	}
	return nil
}

func promptForHostname(opts *LoginOptions) (string, error) {
	options := []string{"GitHub.com", "Other"}
	hostType, err := opts.Prompter.Select(
		"Where do you use GitHub?",
		options[0],
		options)
	if err != nil {
		return "", err
	}

	isGitHubDotCom := hostType == 0
	if isGitHubDotCom {
		return ghinstance.Default(), nil
	}

	return opts.Prompter.InputHostname()
}
