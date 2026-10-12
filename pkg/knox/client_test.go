package knox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtocolAndRedaction(t *testing.T) {
	secret := strings.Repeat("s", 48)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "0u"+strings.Repeat("a", 48) {
			t.Error("Knox auth prefix lost")
		}
		if r.Method == "GET" && r.URL.Path == "/v0/keys/" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": []string{"stepdown:github"}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/access/") {
			_, _ = w.Write([]byte(`{"status":"ok","data":[{"type":"User","id":"operator","access":"Admin"}]}`))
			return
		}
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": map[string]any{"id": "stepdown:github", "acl": []any{}, "versions": []any{map[string]any{"id": 1, "status": "Primary", "ts": 100, "data": base64.StdEncoding.EncodeToString([]byte(secret))}}}})
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("Knox requires form encoding")
		}
		if data := r.Form.Get("data"); data != "" {
			b, err := base64.StdEncoding.DecodeString(data)
			if err != nil || string(b) != secret {
				t.Error("incorrect secret data encoding")
			}
		}
		if r.Method == "POST" {
			_, _ = w.Write([]byte(`{"status":"ok","data":2}`))
		} else {
			_, _ = w.Write([]byte(`{"status":"ok","data":null}`))
		}
	}))
	defer server.Close()
	t.Setenv("KNOX_TEST_AUTH", "0u"+strings.Repeat("a", 48))
	c, err := (Connection{URL: server.URL, AuthEnv: "KNOX_TEST_AUTH", AllowHTTP: true}).New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := c.ReadPrimary(ctx, "stepdown:github")
	if err != nil || v != secret {
		t.Fatal("primary read failed", err)
	}
	for _, cmd := range []Command{{Operation: "list"}, {Operation: "inspect", KeyID: "stepdown:github"}, {Operation: "create", KeyID: "stepdown:github", Value: secret}, {Operation: "add-version", KeyID: "stepdown:github", Value: secret}, {Operation: "set-status", KeyID: "stepdown:github", VersionID: 2, Status: "Primary"}, {Operation: "set-acl", KeyID: "stepdown:github", ACL: []Access{{Type: "Machine", ID: "proxy.example", Access: "Read"}}}} {
		result, err := c.Execute(ctx, cmd)
		if err != nil {
			t.Fatal(cmd.Operation, err)
		}
		b, _ := json.Marshal(result)
		if strings.Contains(string(b), secret) || strings.Contains(string(b), base64.StdEncoding.EncodeToString([]byte(secret))) || strings.Contains(string(b), `"data"`) {
			t.Fatal("management operation exposed secret", cmd.Operation)
		}
	}
}

func TestRejectedCommands(t *testing.T) {
	c := &Client{}
	for _, cmd := range []Command{{Operation: "inspect", KeyID: "../escape"}, {Operation: "delete", KeyID: "key"}, {Operation: "create", KeyID: "key"}, {Operation: "set-status", KeyID: "key", VersionID: 1, Status: "wrong"}, {Operation: "set-status", KeyID: "key", Status: "Primary"}, {Operation: "set-acl", KeyID: "key", ACL: []Access{{Type: "unknown", ID: "x", Access: "Admin"}}}} {
		if _, err := c.Execute(context.Background(), cmd); err == nil {
			t.Fatal("bad command accepted")
		}
	}
}

func TestRedirectAndMalformedResponses(t *testing.T) {
	for _, body := range []string{`{"status":"error","message":"secret"}`, `{}`, `not json`, `{"status":"ok","data":{"id":"wrong","versions":[]}}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		c := &Client{URL: s.URL, HTTP: s.Client(), Authorization: func() (string, error) { return "0utest", nil }}
		if _, err := c.ReadPrimary(context.Background(), "key"); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("bad or sensitive error")
		}
		s.Close()
	}
	var destinationCalls int
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls++ }))
	defer dest.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 302) }))
	defer s.Close()
	c := &Client{URL: s.URL, HTTP: s.Client(), Authorization: func() (string, error) { return "0utest", nil }}
	if _, err := c.Execute(context.Background(), Command{Operation: "list"}); err == nil || destinationCalls != 0 {
		t.Fatal("credential redirect followed")
	}
}

func TestTLSVerificationAndConfig(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok","data":[]}`)) }))
	defer s.Close()
	t.Setenv("KNOX_TEST_AUTH", "0utest")
	c, err := (Connection{URL: s.URL, AuthEnv: "KNOX_TEST_AUTH"}).New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Execute(context.Background(), Command{Operation: "list"}); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	for _, conf := range []Connection{{URL: "http://knox.example", AuthEnv: "KNOX_TEST_AUTH"}, {URL: "https://user:password@knox.example", AuthEnv: "KNOX_TEST_AUTH"}, {URL: "https://knox.example/path", AuthEnv: "KNOX_TEST_AUTH"}, {URL: "https://knox.example", AuthEnv: "x", AuthFile: "y"}, {URL: "https://knox.example", AuthEnv: "x", CertFile: "only-cert"}} {
		if _, err := conf.New(); err == nil {
			t.Fatal("unsafe connection accepted")
		}
	}
}
