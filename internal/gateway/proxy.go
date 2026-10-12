package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const MaxRequest = 1 << 20
const MaxResponse = 8 << 20

type Input struct {
	Principal string              `json:"principal"`
	Service   string              `json:"service"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Query     url.Values          `json:"query"`
	Headers   map[string][]string `json:"headers"`
	Body      any                 `json:"body"`
}
type credential struct {
	id   string
	hash [32]byte
}
type Event struct {
	Time      time.Time `json:"time"`
	Principal string    `json:"principal,omitempty"`
	Service   string    `json:"service,omitempty"`
	Method    string    `json:"method"`
	Status    int       `json:"status"`
	Reason    string    `json:"reason"`
}
type Audit struct {
	mu     sync.Mutex
	events []Event
	Logger *slog.Logger
}

func (a *Audit) Record(e Event) {
	e.Time = time.Now().UTC()
	a.mu.Lock()
	a.events = append(a.events, e)
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
	a.mu.Unlock()
	if a.Logger != nil {
		a.Logger.Info("request", "principal", e.Principal, "service", e.Service, "status", e.Status, "reason", e.Reason)
	}
}
func (a *Audit) Events() []Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Event{}, a.events...)
}

type Gateway struct {
	config   Config
	clients  []credential
	services map[string]Service
	secrets  *Secrets
	http     *http.Client
	audit    *Audit
	slots    chan struct{}
}

func New(c Config, audit *Audit) (*Gateway, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s, err := newSecrets(c)
	if err != nil {
		return nil, err
	}
	h, err := httpClient(nil)
	if err != nil {
		return nil, err
	}
	g := &Gateway{config: c, services: map[string]Service{}, secrets: s, http: h, audit: audit, slots: make(chan struct{}, 32)}
	seen := map[[32]byte]bool{}
	for _, cl := range c.Clients {
		token, err := localSecret(cl.Token)
		if err != nil || len(token) < 32 {
			return nil, errors.New("client credential missing or shorter than 32 bytes")
		}
		hash := sha256.Sum256([]byte(token))
		if seen[hash] {
			return nil, errors.New("clients must have distinct credentials")
		}
		seen[hash] = true
		g.clients = append(g.clients, credential{cl.ID, hash})
	}
	for _, service := range c.Services {
		g.services[service.ID] = service
	}
	return g, nil
}

func Bearer(r *http.Request) string {
	if len(r.Header.Values("Authorization")) != 1 {
		return ""
	}
	s := r.Header.Get("Authorization")
	if !strings.HasPrefix(s, "Bearer ") {
		return ""
	}
	s = strings.TrimPrefix(s, "Bearer ")
	if !validSecret(s) {
		return ""
	}
	return s
}

func (g *Gateway) authenticate(token string) string {
	hash := sha256.Sum256([]byte(token))
	id := ""
	for _, c := range g.clients {
		if subtle.ConstantTimeCompare(hash[:], c.hash[:]) == 1 {
			id = c.id
		}
	}
	return id
}

func Reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (g *Gateway) Evaluate(ctx context.Context, input Input) (bool, error) {
	b, _ := json.Marshal(map[string]any{"input": input})
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", g.config.OPAURL, bytes.NewReader(b))
	if err != nil {
		return false, errors.New("invalid decision request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		return false, errors.New("policy unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("policy unavailable")
	}
	b, err = readBounded(resp.Body, 64<<10)
	if err != nil {
		return false, err
	}
	value, err := ParseJSON(b)
	if err != nil {
		return false, errors.New("invalid policy result")
	}
	result, ok := value.(map[string]any)
	if !ok {
		return false, errors.New("invalid policy result")
	}
	allowed, ok := result["result"].(bool)
	if !ok {
		return false, errors.New("undefined or invalid policy result")
	}
	return allowed, nil
}

var requestHeaders = []string{"Accept", "Content-Type", "If-Match", "If-None-Match", "Idempotency-Key", "X-Github-Api-Version"}
var responseHeaders = []string{"Content-Type", "Etag", "Last-Modified", "Retry-After", "X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset"}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		Reply(w, 200, map[string]string{"status": "ok"})
		return
	}
	e := Event{Status: 500, Reason: "internal_error"}
	defer func() {
		if g.audit != nil {
			g.audit.Record(e)
		}
	}()
	fail := func(status int, reason string) {
		e.Status = status
		e.Reason = reason
		Reply(w, status, map[string]string{"error": reason})
	}
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		e.Method = r.Method
	default:
		fail(400, "unsupported_method")
		return
	}
	token := Bearer(r)
	principal := g.authenticate(token)
	if token == "" || principal == "" {
		fail(401, "unauthorized")
		return
	}
	e.Principal = principal
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		fail(429, "proxy_busy")
		return
	}
	if r.URL.IsAbs() || r.URL.Host != "" || !safePath(r.URL.EscapedPath()) || r.Method == "CONNECT" || r.Method == "TRACE" {
		fail(400, "invalid_request_target")
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
	if len(parts) != 3 || parts[0] != "proxy" {
		fail(404, "unknown_service")
		return
	}
	service, ok := g.services[parts[1]]
	if !ok {
		fail(404, "unknown_service")
		return
	}
	e.Service = service.ID
	path := "/" + parts[2]
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(400, "invalid_query")
		return
	}
	for k := range query {
		switch strings.ToLower(k) {
		case "access_token", "token", "api_key", "apikey", "authorization":
			fail(400, "credential_query_forbidden")
			return
		}
	}
	if r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 {
		fail(400, "unsupported_encoding")
		return
	}
	body, err := readBounded(r.Body, MaxRequest)
	if err != nil {
		fail(413, "request_too_large")
		return
	}
	var parsed any
	if len(body) > 0 {
		if len(r.Header.Values("Content-Type")) != 1 {
			fail(400, "ambiguous_content_type")
			return
		}
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			fail(415, "json_body_required")
			return
		}
		parsed, err = ParseJSON(body)
		if err != nil {
			fail(400, "ambiguous_json")
			return
		}
		body, _ = json.Marshal(parsed)
	}
	headers := map[string][]string{}
	for _, k := range requestHeaders {
		if v := r.Header.Values(k); len(v) > 0 {
			headers[strings.ToLower(k)] = append([]string{}, v...)
		}
	}
	input := Input{principal, service.ID, r.Method, path, query, headers, parsed}
	allowed, err := g.Evaluate(r.Context(), input)
	if err != nil {
		fail(503, "policy_unavailable")
		return
	}
	if !allowed {
		fail(403, "policy_denied")
		return
	}
	secret, err := g.secrets.Get(r.Context(), service.Credential)
	if err != nil {
		fail(503, "credential_unavailable")
		return
	}
	if secret == token {
		fail(503, "credential_separation_required")
		return
	}
	u, _ := url.Parse(service.URL)
	u.Path = path
	u.RawQuery = query.Encode()
	out, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		fail(400, "invalid_request")
		return
	}
	for k, v := range headers {
		out.Header[http.CanonicalHeaderKey(k)] = v
	}
	out.Header.Set("User-Agent", "StepDownproxy/0.1.0")
	out.Header.Set(service.Header, service.Prefix+secret)
	resp, err := g.http.Do(out)
	if err != nil {
		fail(502, "upstream_unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		fail(502, "upstream_redirect_or_upgrade_blocked")
		return
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		fail(502, "upstream_encoding_blocked")
		return
	}
	response, err := readBounded(resp.Body, MaxResponse)
	if err != nil {
		fail(502, "upstream_response_too_large")
		return
	}
	for _, value := range []string{secret, token} {
		if bytes.Contains(response, []byte(value)) {
			fail(502, "credential_echo_blocked")
			return
		}
		for _, h := range responseHeaders {
			for _, v := range resp.Header.Values(h) {
				if strings.Contains(v, value) {
					fail(502, "credential_echo_blocked")
					return
				}
			}
		}
	}
	for _, h := range responseHeaders {
		for _, v := range resp.Header.Values(h) {
			w.Header().Add(h, v)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	e.Status = resp.StatusCode
	e.Reason = "allowed"
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(response)
}
