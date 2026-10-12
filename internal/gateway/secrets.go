package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quentinmayo/StepDownproxy/pkg/knox"
)

func httpClient(b *Backend) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if b != nil && b.CAFile != "" {
		pem, err := os.ReadFile(b.CAFile)
		if err != nil {
			return nil, errors.New("cannot read backend CA")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid backend CA")
		}
		tlsConfig.RootCAs = pool
	}
	if b != nil && b.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(b.CertFile, b.KeyFile)
		if err != nil {
			return nil, errors.New("invalid backend client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:           nil, // Never route a credential through ambient HTTP_PROXY.
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConns: 100, MaxIdleConnsPerHost: 10, IdleConnTimeout: 60 * time.Second,
			DisableCompression: true,
		},
	}, nil
}

func localSecret(r SecretRef) (string, error) {
	var v string
	switch r.Provider {
	case "env":
		v = os.Getenv(r.Ref)
	case "file":
		f, err := os.Open(r.Ref)
		if err != nil {
			return "", errors.New("secret unavailable")
		}
		defer f.Close()
		b, err := readBounded(f, 16<<10)
		if err != nil {
			return "", errors.New("secret unavailable")
		}
		v = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	default:
		return "", errors.New("local reference required")
	}
	if !validSecret(v) {
		return "", errors.New("secret missing or invalid")
	}
	return v, nil
}

func validSecret(s string) bool {
	if len(s) == 0 || len(s) > 16<<10 {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("body unavailable or too large")
	}
	return b, nil
}

type Secrets struct {
	vault     *Backend
	vaultHTTP *http.Client
	knox      *knox.Client
}

func NewKnox(b Backend) (*knox.Client, error) {
	c, err := httpClient(&b)
	if err != nil {
		return nil, err
	}
	return &knox.Client{URL: b.URL, HTTP: c, Authorization: func() (string, error) { return localSecret(b.Token) }}, nil
}

func newSecrets(c Config) (*Secrets, error) {
	s := &Secrets{vault: c.Vault}
	var err error
	if c.Vault != nil {
		s.vaultHTTP, err = httpClient(c.Vault)
		if err != nil {
			return nil, err
		}
	}
	if c.Knox != nil {
		s.knox, err = NewKnox(*c.Knox)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Secrets) Get(ctx context.Context, r SecretRef) (string, error) {
	switch r.Provider {
	case "env", "file":
		return localSecret(r)
	case "knox":
		value, err := s.knox.ReadPrimary(ctx, r.Ref)
		if err != nil {
			return "", err
		}
		if !validSecret(value) {
			return "", errors.New("Knox primary unavailable")
		}
		return value, nil
	case "vault":
		token, err := localSecret(s.vault.Token)
		if err != nil {
			return "", err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.vault.URL, "/")+"/v1/"+r.Ref, nil)
		req.Header.Set("X-Vault-Token", token)
		resp, err := s.vaultHTTP.Do(req)
		if err != nil {
			return "", errors.New("Vault unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", errors.New("Vault read rejected")
		}
		b, err := readBounded(resp.Body, 1<<20)
		if err != nil {
			return "", err
		}
		var result struct {
			Data struct {
				Data map[string]json.RawMessage `json:"data"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &result) != nil {
			return "", errors.New("invalid Vault response")
		}
		var value string
		if json.Unmarshal(result.Data.Data[r.Field], &value) != nil || !validSecret(value) {
			return "", errors.New("Vault field unavailable")
		}
		return value, nil
	}
	return "", errors.New("unknown provider")
}
