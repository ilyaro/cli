// Package onepassword stores gh credentials in a 1Password item through the `op` CLI.
//
// Secrets are only ever passed to `op` on stdin, never as arguments or environment variables.
package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/cli/safeexec"
)

const (
	callTimeout = 2 * time.Minute

	fieldAccessToken  = "access_token"
	fieldRefreshToken = "refresh_token"
	fieldMetadata     = "metadata"
	itemCategory      = "SECURE_NOTE"
)

// Error kinds returned by Client operations.
var (
	ErrUnavailable = errors.New("1Password CLI (op) is not available or not signed in")
	ErrNotFound    = errors.New("1Password item not found")
	ErrMalformed   = errors.New("1Password item is malformed")
	ErrPermission  = errors.New("1Password denied access")
	ErrTimeout     = errors.New("1Password CLI (op) timed out")
)

// Error wraps a failure from the op CLI with its classification. Only the first
// line of op's stderr is kept, and secrets never reach it because they travel on stdin.
type Error struct {
	Kind    error
	Op      string
	Details string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("%s: %s", e.Op, e.Kind)
	if e.Details != "" {
		msg += ": " + e.Details
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Kind }

// Runner executes the op CLI. It exists so tests can avoid a real 1Password.
type Runner interface {
	Run(ctx context.Context, stdin []byte, args ...string) (stdout, stderr []byte, err error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, []byte, error) {
	path, err := safeexec.LookPath("op")
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Ref pins one 1Password item by immutable identifiers.
type Ref struct {
	AccountID string
	VaultID   string
	ItemID    string
}

// Valid reports whether every identifier is set.
func (r Ref) Valid() bool { return r.AccountID != "" && r.VaultID != "" && r.ItemID != "" }

// Secret is the credential payload kept in the item.
type Secret struct {
	AccessToken  string
	RefreshToken string
	// Metadata is opaque, non-secret JSON describing expiry; its meaning belongs to the caller.
	Metadata string
}

// Client talks to 1Password through a Runner.
type Client struct {
	runner Runner
}

// NewClient returns a Client that executes the real op CLI.
func NewClient() *Client { return &Client{runner: execRunner{}} }

// NewClientWithRunner returns a Client using the supplied Runner.
func NewClientWithRunner(r Runner) *Client { return &Client{runner: r} }

func (c *Client) run(ctx context.Context, opName string, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	stdout, stderr, err := c.runner.Run(ctx, stdin, args...)
	if err == nil {
		return stdout, nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, &Error{Kind: ErrTimeout, Op: opName}
	}
	return nil, classify(opName, err, string(stderr))
}

func classify(opName string, err error, stderr string) error {
	msg := strings.TrimSpace(stderr)
	lower := strings.ToLower(msg)
	var execErr *exec.Error
	switch {
	case errors.As(err, &execErr), errors.Is(err, exec.ErrNotFound):
		return &Error{Kind: ErrUnavailable, Op: opName, Details: "op executable not found"}
	case strings.Contains(lower, "isn't an item"), strings.Contains(lower, "not found"), strings.Contains(lower, "no item"):
		return &Error{Kind: ErrNotFound, Op: opName}
	case strings.Contains(lower, "not currently signed in"), strings.Contains(lower, "not signed in"), strings.Contains(lower, "no accounts configured"),
		strings.Contains(lower, "authorization prompt"), strings.Contains(lower, "locked"), strings.Contains(lower, "sign in"):
		return &Error{Kind: ErrUnavailable, Op: opName, Details: firstLine(msg)}
	case strings.Contains(lower, "forbidden"), strings.Contains(lower, "permission"), strings.Contains(lower, "not authorized"):
		return &Error{Kind: ErrPermission, Op: opName, Details: firstLine(msg)}
	}
	return &Error{Kind: err, Op: opName, Details: firstLine(msg)}
}

func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

// Preflight verifies op is installed and signed in, returning the account ID that new items are bound to.
func (c *Client) Preflight(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "op whoami", nil, "whoami", "--format", "json")
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			return "", err
		}
		// With the desktop app integration, whoami reports "not signed in" until some command has requested
		// authorization, while account get triggers the app prompt and returns the account ID.
		out, err = c.run(ctx, "op account get", nil, "account", "get", "--format", "json")
		if err != nil {
			return "", err
		}
		var acct struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(out, &acct); err != nil || acct.ID == "" {
			return "", &Error{Kind: ErrMalformed, Op: "op account get"}
		}
		return acct.ID, nil
	}
	var who struct {
		AccountUUID string `json:"account_uuid"`
	}
	if err := json.Unmarshal(out, &who); err != nil || who.AccountUUID == "" {
		return "", &Error{Kind: ErrMalformed, Op: "op whoami"}
	}
	return who.AccountUUID, nil
}

type itemField struct {
	Label string `json:"label"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type itemDoc struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title,omitempty"`
	Category string `json:"category,omitempty"`
	Vault    *struct {
		ID string `json:"id"`
	} `json:"vault,omitempty"`
	Fields []itemField `json:"fields"`
}

func buildDoc(title string, s Secret) ([]byte, error) {
	doc := itemDoc{Fields: []itemField{
		{Label: fieldAccessToken, Type: "CONCEALED", Value: s.AccessToken},
		{Label: fieldRefreshToken, Type: "CONCEALED", Value: s.RefreshToken},
		{Label: fieldMetadata, Type: "STRING", Value: s.Metadata},
	}}
	if title != "" {
		doc.Title = title
		doc.Category = itemCategory
	}
	return json.Marshal(doc)
}

func parseItem(opName string, out []byte) (itemID, vaultID string, s Secret, err error) {
	var doc itemDoc
	if err := json.Unmarshal(out, &doc); err != nil || doc.ID == "" || doc.Vault == nil || doc.Vault.ID == "" {
		return "", "", Secret{}, &Error{Kind: ErrMalformed, Op: opName}
	}
	for _, f := range doc.Fields {
		switch f.Label {
		case fieldAccessToken:
			s.AccessToken = f.Value
		case fieldRefreshToken:
			s.RefreshToken = f.Value
		case fieldMetadata:
			s.Metadata = f.Value
		}
	}
	return doc.ID, doc.Vault.ID, s, nil
}

// Create saves a new item in the account's built-in default vault and returns its immutable reference.
func (c *Client) Create(ctx context.Context, accountID, title string, s Secret) (Ref, error) {
	body, err := buildDoc(title, s)
	if err != nil {
		return Ref{}, err
	}
	out, err := c.run(ctx, "op item create", body, "item", "create", "--account", accountID, "--format", "json")
	if err != nil {
		return Ref{}, err
	}
	itemID, vaultID, _, err := parseItem("op item create", out)
	if err != nil {
		return Ref{}, err
	}
	return Ref{AccountID: accountID, VaultID: vaultID, ItemID: itemID}, nil
}

// Get reads the item identified by ref and validates its identity and schema.
func (c *Client) Get(ctx context.Context, ref Ref) (Secret, error) {
	if !ref.Valid() {
		return Secret{}, &Error{Kind: ErrMalformed, Op: "op item get", Details: "incomplete item reference"}
	}
	out, err := c.run(ctx, "op item get", nil, "item", "get", ref.ItemID,
		"--vault", ref.VaultID, "--account", ref.AccountID, "--format", "json", "--reveal")
	if err != nil {
		return Secret{}, err
	}
	itemID, vaultID, s, err := parseItem("op item get", out)
	if err != nil {
		return Secret{}, err
	}
	if itemID != ref.ItemID || vaultID != ref.VaultID || s.AccessToken == "" {
		return Secret{}, &Error{Kind: ErrMalformed, Op: "op item get"}
	}
	return s, nil
}

// Update replaces the secret stored in the item identified by ref.
func (c *Client) Update(ctx context.Context, ref Ref, s Secret) error {
	if !ref.Valid() {
		return &Error{Kind: ErrMalformed, Op: "op item edit", Details: "incomplete item reference"}
	}
	body, err := buildDoc("", s)
	if err != nil {
		return err
	}
	_, err = c.run(ctx, "op item edit", body, "item", "edit", ref.ItemID,
		"--vault", ref.VaultID, "--account", ref.AccountID, "--format", "json")
	return err
}

// Delete removes the item identified by ref. A missing item is not an error.
func (c *Client) Delete(ctx context.Context, ref Ref) error {
	if !ref.Valid() {
		return nil
	}
	_, err := c.run(ctx, "op item delete", nil, "item", "delete", ref.ItemID,
		"--vault", ref.VaultID, "--account", ref.AccountID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
