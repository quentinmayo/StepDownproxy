package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

//go:embed web/*
var web embed.FS

type Manager struct {
	current   atomic.Pointer[Gateway]
	mu        sync.Mutex
	config    Config
	statePath string
	audit     *Audit
}

func NewManager(c Config, statePath string, audit *Audit) (*Manager, error) {
	if audit == nil {
		audit = &Audit{}
	}
	if statePath != "" {
		b, err := os.ReadFile(statePath)
		if err == nil {
			var state struct {
				Services []Service `json:"services"`
			}
			if len(b) > 1<<20 || DecodeStrict(b, &state) != nil {
				return nil, errors.New("invalid saved asset configuration")
			}
			c.Services = state.Services
		} else if !os.IsNotExist(err) {
			return nil, errors.New("cannot read saved assets")
		}
	}
	if c.Services == nil {
		c.Services = []Service{}
	}
	g, err := New(c, audit)
	if err != nil {
		return nil, err
	}
	m := &Manager{config: c, statePath: statePath, audit: audit}
	m.current.Store(g)
	return m, nil
}
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.current.Load().ServeHTTP(w, r) }

func (m *Manager) save(services []Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.config
	c.Services = services
	g, err := New(c, m.audit)
	if err != nil {
		return err
	}
	if m.statePath == "" {
		return errors.New("asset persistence is not configured")
	}
	b, _ := json.MarshalIndent(map[string]any{"services": services}, "", "  ")
	f, err := os.CreateTemp(filepath.Dir(m.statePath), ".assets-*")
	if err != nil {
		return errors.New("cannot create asset state")
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot persist asset state")
	}
	if os.Rename(f.Name(), m.statePath) != nil {
		return errors.New("cannot replace asset state")
	}
	m.config = c
	old := m.current.Swap(g)
	old.http.CloseIdleConnections()
	return nil
}

// SameOrigin adds defense in depth to APIs authenticated by explicit Bearer
// headers. No cookies, CORS, or browser credential persistence are used.
func SameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
			return false
		}
	}
	return true
}

func (m *Manager) Admin(tokenRef SecretRef) (http.Handler, error) {
	token, err := localSecret(tokenRef)
	if err != nil || len(token) < 32 {
		return nil, errors.New("admin credential needs at least 32 bytes")
	}
	hash := sha256.Sum256([]byte(token))
	for _, c := range m.current.Load().clients {
		if subtle.ConstantTimeCompare(hash[:], c.hash[:]) == 1 {
			return nil, errors.New("admin and proxy credentials must differ")
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css") {
			name := r.URL.Path[1:]
			if name == "" {
				name = "index.html"
			}
			b, _ := web.ReadFile("web/" + name)
			switch name {
			case "index.html":
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
			case "app.js":
				w.Header().Set("Content-Type", "text/javascript")
			default:
				w.Header().Set("Content-Type", "text/css")
			}
			_, _ = w.Write(b)
			return
		}
		t := Bearer(r)
		got := sha256.Sum256([]byte(t))
		if t == "" || subtle.ConstantTimeCompare(got[:], hash[:]) != 1 {
			Reply(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if !SameOrigin(r) {
			Reply(w, 403, map[string]string{"error": "cross_origin_forbidden"})
			return
		}
		switch {
		case r.URL.Path == "/api/overview" && r.Method == "GET":
			m.mu.Lock()
			c := m.config
			m.mu.Unlock()
			clients := []string{}
			for _, cl := range c.Clients {
				clients = append(clients, cl.ID)
			}
			Reply(w, 200, map[string]any{"services": c.Services, "clients": clients, "opa_url": c.OPAURL, "knox_enabled": c.Knox != nil, "events": m.audit.Events()})
		case r.URL.Path == "/api/assets" && r.Method == "PUT":
			var v struct {
				Services []Service `json:"services"`
			}
			b, err := readBounded(r.Body, MaxRequest)
			if err != nil || DecodeStrict(b, &v) != nil || v.Services == nil {
				Reply(w, 400, map[string]string{"error": "invalid_assets"})
				return
			}
			err = m.save(v.Services)
			if err != nil {
				Reply(w, 400, map[string]string{"error": err.Error()})
				return
			}
			m.audit.Record(Event{Principal: "admin", Method: "PUT", Status: 200, Reason: "assets_updated"})
			Reply(w, 200, map[string]bool{"ok": true})
		case r.URL.Path == "/api/evaluate" && r.Method == "POST":
			var input Input
			b, err := readBounded(r.Body, MaxRequest)
			if err != nil || DecodeStrict(b, &input) != nil {
				Reply(w, 400, map[string]string{"error": "invalid_input"})
				return
			}
			allow, err := m.current.Load().Evaluate(r.Context(), input)
			if err != nil {
				Reply(w, 503, map[string]string{"error": "policy_unavailable"})
				return
			}
			Reply(w, 200, map[string]bool{"allow": allow})
		default:
			Reply(w, 404, map[string]string{"error": "not_found"})
		}
	}), nil
}
