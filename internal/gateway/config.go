package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Config contains references to credentials, never credential values.
type Config struct {
	Listen    string    `json:"listen"`
	OPAURL    string    `json:"opa_url"`
	AllowHTTP bool      `json:"allow_http"`
	Clients   []Client  `json:"clients"`
	Services  []Service `json:"services"`
	Vault     *Backend  `json:"vault,omitempty"`
	Knox      *Backend  `json:"knox,omitempty"`
}

type Client struct {
	ID    string    `json:"id"`
	Token SecretRef `json:"token"`
}

type SecretRef struct {
	Provider string `json:"provider"`
	Ref      string `json:"ref"`
	Field    string `json:"field,omitempty"`
}

type Service struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	Credential SecretRef `json:"credential"`
	Header     string    `json:"header"`
	Prefix     string    `json:"prefix"`
}

// Backend supports Knox authorization tokens (including 0u/0m/0t prefixes),
// custom CAs, and client certificates without disabling TLS verification.
type Backend struct {
	URL      string    `json:"url"`
	Token    SecretRef `json:"token"`
	CAFile   string    `json:"ca_file,omitempty"`
	CertFile string    `json:"cert_file,omitempty"`
	KeyFile  string    `json:"key_file,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var keyIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_:.-]{0,255}$`)
var canonicalPath = regexp.MustCompile(`^/[a-zA-Z0-9_./~-]*$`)

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("cannot read configuration")
	}
	if len(b) > 1<<20 {
		return c, errors.New("configuration too large")
	}
	err = DecodeStrict(b, &c)
	return c, err
}

func DecodeStrict(b []byte, dst any) error {
	if _, err := ParseJSON(b); err != nil {
		return errors.New("invalid or ambiguous JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return errors.New("invalid configuration fields or types")
	}
	return nil
}

// ParseJSON rejects duplicate object keys at every level and preserves numbers.
// This prevents OPA and an upstream parser from seeing different operations.
func ParseJSON(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		if depth > 64 {
			return nil, errors.New("JSON nesting too deep")
		}
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch t {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				s, ok := k.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				if _, exists := m[s]; exists {
					return nil, errors.New("duplicate object key")
				}
				v, err := walk(depth + 1)
				if err != nil {
					return nil, err
				}
				m[s] = v
			}
			_, err := d.Token()
			return m, err
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := walk(depth + 1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		default:
			if _, ok := t.(json.Delim); ok {
				return nil, errors.New("invalid delimiter")
			}
			return t, nil
		}
	}
	v, err := walk(0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}

func validURL(raw string, allowHTTP bool, originOnly bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("URL must have a host and no credentials, query, or fragment")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return errors.New("HTTPS required; allow_http is for isolated development")
	}
	if originOnly && u.Path != "" && u.Path != "/" {
		return errors.New("service and backend URLs must be origins without path prefixes")
	}
	return nil
}

func localRef(r SecretRef) bool {
	return (r.Provider == "env" || r.Provider == "file") && r.Ref != "" && r.Field == ""
}

func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen address required")
	}
	if err := validURL(c.OPAURL, c.AllowHTTP, false); err != nil {
		return err
	}
	u, _ := url.Parse(c.OPAURL)
	if !strings.HasPrefix(u.Path, "/v1/data/") {
		return errors.New("opa_url must identify a /v1/data/ decision")
	}
	if len(c.Clients) == 0 || len(c.Clients) > 1000 || len(c.Services) > 1000 {
		return errors.New("one to 1000 clients and at most 1000 services required")
	}
	ids := map[string]bool{}
	for _, v := range c.Clients {
		if !identifier.MatchString(v.ID) || ids[v.ID] || !localRef(v.Token) {
			return errors.New("invalid or duplicate client; client token must reference env or file")
		}
		ids[v.ID] = true
	}
	for _, b := range []*Backend{c.Vault, c.Knox} {
		if b == nil {
			continue
		}
		if err := validURL(b.URL, c.AllowHTTP, true); err != nil {
			return err
		}
		if !localRef(b.Token) || (b.CertFile == "") != (b.KeyFile == "") {
			return errors.New("backend needs a local token reference and paired TLS certificate/key")
		}
	}
	ids = map[string]bool{}
	for _, s := range c.Services {
		if !identifier.MatchString(s.ID) || ids[s.ID] {
			return errors.New("invalid or duplicate service ID")
		}
		ids[s.ID] = true
		if err := validURL(s.URL, c.AllowHTTP, true); err != nil {
			return err
		}
		h := strings.ToLower(s.Header)
		if h != "authorization" && h != "x-api-key" && h != "private-token" {
			return errors.New("credential header must be Authorization, X-API-Key, or Private-Token")
		}
		if strings.ContainsAny(s.Prefix, "\r\n") || len(s.Prefix) > 32 {
			return errors.New("invalid credential prefix")
		}
		r := s.Credential
		switch r.Provider {
		case "env", "file":
			if !localRef(r) {
				return errors.New("invalid local secret reference")
			}
		case "vault":
			if c.Vault == nil || r.Field == "" || !safePath("/"+r.Ref) || strings.HasPrefix(r.Ref, "/") || !strings.Contains(r.Ref, "/data/") {
				return errors.New("Vault KV v2 needs a backend, mount/data/path reference, and field")
			}
		case "knox":
			if c.Knox == nil || !keyIdentifier.MatchString(r.Ref) || r.Field != "" {
				return errors.New("invalid Knox key reference or missing backend")
			}
		default:
			return errors.New("unknown credential provider")
		}
	}
	return nil
}

func safePath(p string) bool {
	if !canonicalPath.MatchString(p) || strings.Contains(p, "//") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}
