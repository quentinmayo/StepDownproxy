package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type fixture struct {
	g              *Gateway
	config         Config
	client, secret string
	calls          atomic.Int32
	input          Input
	audit          *Audit
	logs           bytes.Buffer
}

func setup(t *testing.T, decision string, upstream http.HandlerFunc) *fixture {
	t.Helper()
	f := &fixture{client: strings.Repeat("c", 48), secret: strings.Repeat("u", 48)}
	t.Setenv("TEST_CLIENT", f.client)
	t.Setenv("TEST_UPSTREAM", f.secret)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if upstream != nil {
			upstream(w, r)
		} else {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(up.Close)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Input Input `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&v)
		f.input = v.Input
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(decision))
	}))
	t.Cleanup(opa.Close)
	f.config = Config{Listen: "127.0.0.1:8080", OPAURL: opa.URL + "/v1/data/stepdown/allow", AllowHTTP: true, Clients: []Client{{ID: "reader", Token: SecretRef{Provider: "env", Ref: "TEST_CLIENT"}}}, Services: []Service{{ID: "github", URL: up.URL, Credential: SecretRef{Provider: "env", Ref: "TEST_UPSTREAM"}, Header: "Authorization", Prefix: "Bearer "}}}
	f.audit = &Audit{Logger: slog.New(slog.NewJSONHandler(&f.logs, nil))}
	var err error
	f.g, err = New(f.config, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) request(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.client)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.g.ServeHTTP(w, r)
	return w
}

func TestInjectionAndPolicyIdentity(t *testing.T) {
	f := setup(t, `{"result":true}`, nil)
	f.g.http.Transport = &assertTransport{t: t, token: f.secret, client: f.client, base: f.config.Services[0].URL, fallback: f.g.http.Transport}
	w := f.request("POST", "/proxy/github/repos/example/project/issues?state=open", `{"title":"hello"}`, map[string]string{"Content-Type": "application/json", "Cookie": "bad", "X-Principal": "admin", "X-HTTP-Method-Override": "DELETE", "X-Github-Api-Version": "2022-11-28"})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if f.input.Principal != "reader" || f.input.Method != "POST" || f.input.Path != "/repos/example/project/issues" || f.input.Query.Get("state") != "open" {
		t.Fatalf("wrong policy input: %#v", f.input)
	}
	b, _ := json.Marshal(f.input)
	if bytes.Contains(b, []byte(f.client)) || bytes.Contains(b, []byte(f.secret)) {
		t.Fatal("policy received credential")
	}
	if strings.Contains(f.logs.String(), f.client) || strings.Contains(f.logs.String(), f.secret) || strings.Contains(f.logs.String(), "hello") || strings.Contains(f.logs.String(), "state") {
		t.Fatal("audit leaked sensitive data")
	}
}

type assertTransport struct {
	t                   *testing.T
	token, client, base string
	fallback            http.RoundTripper
}

func (a *assertTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.String(), a.base) {
		return a.fallback.RoundTrip(r)
	}
	a.t.Helper()
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		a.t.Error("upstream credential not injected")
	}
	for _, h := range []string{"Cookie", "X-Principal", "X-HTTP-Method-Override", "Proxy-Authorization", "X-Forwarded-For"} {
		if r.Header.Get(h) != "" {
			a.t.Errorf("unsafe header forwarded: %s", h)
		}
	}
	if !strings.HasPrefix(r.URL.String(), a.base+"/repos/") {
		a.t.Error("target changed")
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
}

func TestFailClosedPolicy(t *testing.T) {
	for _, decision := range []string{`{"result":false}`, `{}`, `{"result":null}`, `{"result":"true"}`, `{"result":{"allow":true}}`, `{"result":false,"result":true}`, `bad`} {
		t.Run(decision, func(t *testing.T) {
			f := setup(t, decision, nil)
			t.Setenv("TEST_UPSTREAM", "")
			w := f.request("GET", "/proxy/github/repos/example/project/issues", "", nil)
			want := 503
			if decision == `{"result":false}` {
				want = 403
			}
			if w.Code != want || f.calls.Load() != 0 {
				t.Fatalf("status %d, calls %d", w.Code, f.calls.Load())
			}
		})
	}
}

func TestTargetAndBodyBypasses(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		headers                  map[string]string
		status                   int
	}{
		{"traversal", "GET", "/proxy/github/../admin", "", nil, 400},
		{"escaped dots", "GET", "/proxy/github/%2e%2e/admin", "", nil, 400},
		{"encoded separator", "GET", "/proxy/github/repos%2fother", "", nil, 400},
		{"double encoding", "GET", "/proxy/github/%252e%252e/admin", "", nil, 400},
		{"duplicate slash", "GET", "/proxy/github//admin", "", nil, 400},
		{"backslash", "GET", "/proxy/github/a%5cb", "", nil, 400},
		{"absolute target", "GET", "http://evil.example/proxy/github/a", "", nil, 400},
		{"connect", "CONNECT", "/proxy/github/a", "", nil, 400},
		{"trace", "TRACE", "/proxy/github/a", "", nil, 400},
		{"unknown service", "GET", "/proxy/evil/a", "", nil, 404},
		{"credential query", "GET", "/proxy/github/a?access_token=bad", "", nil, 400},
		{"bad query", "GET", "/proxy/github/a?bad=%zz", "", nil, 400},
		{"duplicate JSON", "POST", "/proxy/github/a", `{"role":"read","role":"admin"}`, map[string]string{"Content-Type": "application/json"}, 400},
		{"nested duplicate JSON", "POST", "/proxy/github/a", `{"a":{"role":1,"role":2}}`, map[string]string{"Content-Type": "application/json"}, 400},
		{"trailing JSON", "POST", "/proxy/github/a", `{} {}`, map[string]string{"Content-Type": "application/json"}, 400},
		{"form body", "POST", "/proxy/github/a", "a=b", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, 415},
		{"compression", "POST", "/proxy/github/a", "", map[string]string{"Content-Encoding": "gzip"}, 400},
		{"oversized body", "POST", "/proxy/github/a", strings.Repeat("x", MaxRequest+1), nil, 413},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, `{"result":true}`, nil)
			w := f.request(tc.method, tc.path, tc.body, tc.headers)
			if w.Code != tc.status || f.calls.Load() != 0 {
				t.Fatalf("status %d want %d; calls %d", w.Code, tc.status, f.calls.Load())
			}
		})
	}
}

func TestUpstreamResponseSafety(t *testing.T) {
	for _, mode := range []string{"redirect", "echo secret", "echo caller", "header echo", "oversized", "compressed", "cookie"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t, `{"result":true}`, func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://evil.example")
					w.WriteHeader(302)
				case "echo secret":
					_, _ = w.Write([]byte(os.Getenv("TEST_UPSTREAM")))
				case "echo caller":
					_, _ = w.Write([]byte(os.Getenv("TEST_CLIENT")))
				case "header echo":
					w.Header().Set("Etag", os.Getenv("TEST_UPSTREAM"))
				case "oversized":
					_, _ = w.Write(bytes.Repeat([]byte("x"), MaxResponse+1))
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "cookie":
					w.Header().Set("Set-Cookie", "session=bad")
					_, _ = w.Write([]byte(`{}`))
				}
			})
			w := f.request("GET", "/proxy/github/a", "", nil)
			want := 502
			if mode == "cookie" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("status %d want %d", w.Code, want)
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), f.secret) || strings.Contains(w.Body.String(), f.client) {
				t.Fatal("unsafe response escaped")
			}
		})
	}
}

func TestAuthentication(t *testing.T) {
	f := setup(t, `{"result":true}`, nil)
	for _, value := range []string{"", "Bearer wrong", "Basic " + f.client} {
		w := f.request("GET", "/proxy/github/a", "", map[string]string{"Authorization": value})
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/proxy/github/a", nil)
	r.Header.Add("Authorization", "Bearer "+f.client)
	r.Header.Add("Authorization", "Bearer "+f.client)
	w := httptest.NewRecorder()
	f.g.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate authorization accepted")
	}
	if f.calls.Load() != 0 {
		t.Fatal("unauthenticated request reached upstream")
	}
}

func TestAdminPersistenceAndSeparation(t *testing.T) {
	f := setup(t, `{"result":false}`, nil)
	state := filepath.Join(t.TempDir(), "assets.json")
	m, err := NewManager(f.config, state, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_ADMIN", strings.Repeat("a", 48))
	admin, err := m.Admin(SecretRef{Provider: "env", Ref: "TEST_ADMIN"})
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path, token, body, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, r)
		return w
	}
	if send("GET", "/api/overview", f.client, "", "").Code != 401 {
		t.Fatal("caller can administer")
	}
	if send("PUT", "/api/assets", os.Getenv("TEST_ADMIN"), `{"services":[]}`, "https://evil.example").Code != 403 {
		t.Fatal("cross-origin mutation accepted")
	}
	if send("PUT", "/api/assets", os.Getenv("TEST_ADMIN"), `{"services":[{"id":"bad"}]}`, "").Code != 400 {
		t.Fatal("invalid asset accepted")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("invalid mutation persisted")
	}
	if send("PUT", "/api/assets", os.Getenv("TEST_ADMIN"), `{"services":[]}`, "").Code != 200 {
		t.Fatal("save failed")
	}
	restarted, err := NewManager(f.config, state, f.audit)
	if err != nil || len(restarted.config.Services) != 0 {
		t.Fatal("saved assets not restored")
	}
	info, _ := os.Stat(state)
	if info.Mode().Perm() != 0600 {
		t.Fatal("asset state is not private")
	}
	if _, err := m.Admin(SecretRef{Provider: "env", Ref: "TEST_CLIENT"}); err == nil {
		t.Fatal("shared admin credential accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	f := setup(t, `{"result":false}`, nil)
	c := f.config
	c.AllowHTTP = false
	if c.Validate() == nil {
		t.Fatal("insecure URLs accepted by default")
	}
	c = f.config
	c.Services = append(c.Services, c.Services[0])
	if c.Validate() == nil {
		t.Fatal("duplicate service accepted")
	}
	for _, data := range []string{`{"listen":":8080","unknown":true}`, `{"listen":"a","listen":"b"}`, `{} {}`} {
		var c Config
		if DecodeStrict([]byte(data), &c) == nil {
			t.Fatal("bad config accepted")
		}
	}
}

func TestVaultRotationAndErrors(t *testing.T) {
	f := setup(t, `{"result":true}`, nil)
	t.Setenv("VAULT_TEST_AUTH", strings.Repeat("v", 48))
	var requests atomic.Int32
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/github" || r.Header.Get("X-Vault-Token") != os.Getenv("VAULT_TEST_AUTH") {
			t.Error("incorrect Vault request")
		}
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"token": os.Getenv("TEST_UPSTREAM")}}})
	}))
	defer vault.Close()
	c := f.config
	c.Vault = &Backend{URL: vault.URL, Token: SecretRef{Provider: "env", Ref: "VAULT_TEST_AUTH"}}
	c.Services[0].Credential = SecretRef{Provider: "vault", Ref: "secret/data/github", Field: "token"}
	g, err := New(c, f.audit)
	if err != nil {
		t.Fatal(err)
	}
	f.g = g
	for i := 0; i < 2; i++ {
		if f.request("GET", "/proxy/github/a", "", nil).Code != 200 {
			t.Fatal("Vault read failed")
		}
		t.Setenv("TEST_UPSTREAM", strings.Repeat("r", 48))
	}
	if requests.Load() != 2 {
		t.Fatal("Vault credential cached across requests")
	}
	vault.Close()
	if f.request("GET", "/proxy/github/a", "", nil).Code != 503 {
		t.Fatal("Vault failure did not fail closed")
	}
}
