package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewServerRejectsUnknownDefaultUser(t *testing.T) {
	t.Parallel()

	_, err := NewServer(Config{
		StorePath:   filepath.Join(t.TempDir(), "ledger.json"),
		DefaultUser: "ada",
	})
	if err == nil {
		t.Fatal("expected NewServer to reject an unknown default user")
	}
	if !strings.Contains(err.Error(), `default user "ada" is not registered`) {
		t.Fatalf("expected default-user validation error, got %v", err)
	}
}

func TestAPIUsesDefaultUserWhenHeaderMissing(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, "savio")
	body := strings.NewReader(`{"id":"heidi","display":"Heidi","claims":["OPENDEMOCRACY:COMMUNITY"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/participants", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d (%s)", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var got Participant
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ID != "heidi" {
		t.Fatalf("expected participant heidi, got %#v", got)
	}
	if _, err := srv.registry.Get("heidi"); err != nil {
		t.Fatalf("expected registry to contain created participant: %v", err)
	}
}

func TestDashboardActionUsesDefaultUserWhenFormUserMissing(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, "savio")
	form := url.Values{
		"id":      {"judy"},
		"display": {"Judy"},
		"claims":  {"OPENDEMOCRACY:COMMUNITY"},
	}
	req := httptest.NewRequest(http.MethodPost, "/actions/add-participant", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected %d, got %d (%s)", http.StatusSeeOther, rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/participants?flash=ok" {
		t.Fatalf("expected successful redirect, got %q", got)
	}
	if _, err := srv.registry.Get("judy"); err != nil {
		t.Fatalf("expected registry to contain added participant: %v", err)
	}
}

func newTestServer(t *testing.T, defaultUser string) *Server {
	t.Helper()

	srv, err := NewServer(Config{
		StorePath:   filepath.Join(t.TempDir(), "ledger.json"),
		DefaultUser: defaultUser,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}
