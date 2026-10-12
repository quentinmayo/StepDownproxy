// Package knox implements Pinterest Knox's v0 HTTP protocol. It never exposes
// key material from management operations; ReadPrimary is for trusted services.
package knox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type Client struct {
	URL           string
	HTTP          *http.Client
	Authorization func() (string, error)
}

type Access struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Access string `json:"access"`
}
type Version struct {
	ID      uint64 `json:"id,string"`
	Status  string `json:"status"`
	Created int64  `json:"ts"`
}
type Metadata struct {
	ID       string    `json:"id"`
	ACL      []Access  `json:"acl"`
	Versions []Version `json:"versions"`
}
type rawKey struct {
	ID       string   `json:"id"`
	ACL      []Access `json:"acl"`
	Versions []struct {
		ID      uint64 `json:"id"`
		Status  string `json:"status"`
		Created int64  `json:"ts"`
		Data    []byte `json:"data"`
	} `json:"versions"`
}
type Command struct {
	Operation string   `json:"operation"`
	KeyID     string   `json:"key_id,omitempty"`
	Value     string   `json:"value,omitempty"`
	ACL       []Access `json:"acl,omitempty"`
	VersionID uint64   `json:"version_id,omitempty,string"`
	Status    string   `json:"status,omitempty"`
}

var keyID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_:.-]{0,255}$`)

func (c *Client) call(ctx context.Context, method, path string, form url.Values, dst any) error {
	if c.HTTP == nil || c.Authorization == nil {
		return errors.New("Knox client unconfigured")
	}
	token, err := c.Authorization()
	if err != nil || token == "" {
		return errors.New("Knox authentication unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("invalid Knox request")
	}
	req.Header.Set("Authorization", token) // Knox uses 0u/0m/0t, not Bearer.
	req.Header.Set("User-Agent", "StepDownproxy-Knox/0.1.0")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	// Clone so even a supplied client cannot redirect a Knox credential.
	client := *c.HTTP
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Knox unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("Knox operation rejected")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return errors.New("invalid Knox response size")
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(b, &envelope) != nil || envelope.Status != "ok" {
		return errors.New("invalid Knox response")
	}
	if dst != nil && json.Unmarshal(envelope.Data, dst) != nil {
		return errors.New("invalid Knox result")
	}
	return nil
}

func (c *Client) read(ctx context.Context, id string) (rawKey, error) {
	var k rawKey
	if !keyID.MatchString(id) {
		return k, errors.New("invalid Knox key ID")
	}
	err := c.call(ctx, "GET", "/v0/keys/"+id+"/?status=%22Inactive%22", nil, &k)
	if err == nil && k.ID != id {
		err = errors.New("Knox key ID mismatch")
	}
	return k, err
}

func (c *Client) ReadPrimary(ctx context.Context, id string) (string, error) {
	if !keyID.MatchString(id) {
		return "", errors.New("invalid Knox key ID")
	}
	var k rawKey
	if err := c.call(ctx, "GET", "/v0/keys/"+id+"/?status=%22Primary%22", nil, &k); err != nil {
		return "", err
	}
	if k.ID != id || len(k.Versions) != 1 || k.Versions[0].Status != "Primary" || len(k.Versions[0].Data) == 0 {
		return "", errors.New("Knox primary unavailable or ambiguous")
	}
	return string(k.Versions[0].Data), nil
}

func validateACL(acl []Access) bool {
	if len(acl) > 1000 {
		return false
	}
	for _, a := range acl {
		if a.ID == "" || len(a.ID) > 512 {
			return false
		}
		switch a.Type {
		case "User", "UserGroup", "Machine", "MachinePrefix", "Service", "ServicePrefix":
		default:
			return false
		}
		switch a.Access {
		case "None", "Read", "Write", "Admin":
		default:
			return false
		}
	}
	return true
}

// Execute returns only IDs, metadata, or success. Secret data is write-only.
// Knox itself enforces the authenticated principal's ACL on every operation.
func (c *Client) Execute(ctx context.Context, cmd Command) (any, error) {
	if cmd.Operation == "list" {
		var ids []string
		err := c.call(ctx, "GET", "/v0/keys/", nil, &ids)
		return ids, err
	}
	if !keyID.MatchString(cmd.KeyID) {
		return nil, errors.New("invalid Knox key ID")
	}
	path := "/v0/keys/" + cmd.KeyID + "/"
	form := url.Values{}
	switch cmd.Operation {
	case "inspect":
		k, err := c.read(ctx, cmd.KeyID)
		if err != nil {
			return nil, err
		}
		// Knox deliberately clears ACLs on key reads. Fetch its access endpoint
		// separately so inventory shows the actual grants.
		if err := c.call(ctx, "GET", path+"access/", nil, &k.ACL); err != nil {
			return nil, err
		}
		m := Metadata{ID: k.ID, ACL: k.ACL, Versions: []Version{}}
		for _, v := range k.Versions {
			m.Versions = append(m.Versions, Version{v.ID, v.Status, v.Created})
		}
		return m, nil
	case "create", "add-version":
		if cmd.Value == "" || len(cmd.Value) > 16<<10 {
			return nil, errors.New("secret must contain 1 to 16384 bytes")
		}
		form.Set("data", base64.StdEncoding.EncodeToString([]byte(cmd.Value)))
		if cmd.Operation == "create" {
			if !validateACL(cmd.ACL) {
				return nil, errors.New("invalid ACL")
			}
			acl := cmd.ACL
			if acl == nil {
				acl = []Access{}
			}
			b, _ := json.Marshal(acl)
			form.Set("acl", string(b))
			form.Set("id", cmd.KeyID)
			path = "/v0/keys/"
		} else {
			path += "versions/"
		}
		var id uint64
		err := c.call(ctx, "POST", path, form, &id)
		return map[string]string{"version_id": strconv.FormatUint(id, 10)}, err
	case "set-status":
		if cmd.VersionID == 0 {
			return nil, errors.New("version ID required")
		}
		switch cmd.Status {
		case "Primary", "Active", "Inactive":
		default:
			return nil, errors.New("invalid version status")
		}
		b, _ := json.Marshal(cmd.Status)
		form.Set("status", string(b))
		if err := c.call(ctx, "PUT", path+"versions/"+strconv.FormatUint(cmd.VersionID, 10)+"/", form, nil); err != nil {
			return nil, err
		}
	case "set-acl":
		if len(cmd.ACL) == 0 || !validateACL(cmd.ACL) {
			return nil, errors.New("ACL entries required")
		}
		b, _ := json.Marshal(cmd.ACL)
		form.Set("acl", string(b))
		if err := c.call(ctx, "PUT", path+"access/", form, nil); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown Knox operation")
	}
	return map[string]bool{"ok": true}, nil
}
