package knox

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Connection configures a verified HTTPS Knox connection. AuthEnv/AuthFile
// contain the complete Knox authorization string, for example 0u followed by a
// user credential, or 0t followed by the machine name for certificate auth.
type Connection struct {
	URL       string `json:"url"`
	AuthEnv   string `json:"auth_env,omitempty"`
	AuthFile  string `json:"auth_file,omitempty"`
	CAFile    string `json:"ca_file,omitempty"`
	CertFile  string `json:"cert_file,omitempty"`
	KeyFile   string `json:"key_file,omitempty"`
	AllowHTTP bool   `json:"allow_http,omitempty"`
}

func (c Connection) New() (*Client, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http")) {
		return nil, errors.New("Knox URL must be an HTTPS origin; HTTP requires explicit development opt-in")
	}
	if (c.AuthEnv == "") == (c.AuthFile == "") {
		return nil, errors.New("exactly one Knox auth_env or auth_file required")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("paired client certificate and key required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		b, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, errors.New("Knox CA unavailable")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid Knox CA")
		}
		tlsConfig.RootCAs = pool
	}
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, errors.New("Knox client certificate unavailable")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	h := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableCompression: true}}
	return &Client{URL: c.URL, HTTP: h, Authorization: func() (string, error) {
		value := os.Getenv(c.AuthEnv)
		if c.AuthFile != "" {
			f, err := os.Open(c.AuthFile)
			if err != nil {
				return "", errors.New("Knox auth unavailable")
			}
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
			if err != nil {
				return "", errors.New("Knox auth unavailable")
			}
			value = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		}
		if len(value) < 3 || len(value) > 16<<10 {
			return "", errors.New("invalid Knox auth")
		}
		for _, r := range value {
			if r < 33 || r > 126 {
				return "", errors.New("invalid Knox auth")
			}
		}
		return value, nil
	}}, nil
}
