package gateway

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"open-democracy/chaincode/bill"
)

//go:embed web/templates/*.html web/static/*
var webFS embed.FS

// Config holds runtime configuration for the gateway. Fields map directly to
// environment variables read by cmd/gateway/main.go.
type Config struct {
	Addr      string // listen address, e.g. :8080
	StorePath string // path to JSON-backed store file
	DefaultUser string // default participant id when X-User is missing
}

// Server is the gateway HTTP server. It owns the persisted store, the bill
// service, the participant registry, and the event broadcaster, and exposes
// both a REST API and a server-rendered dashboard.
type Server struct {
	cfg         Config
	store       *PersistedStore
	svc         *bill.Service
	registry    *Registry
	broadcaster *Broadcaster
	templates   map[string]*template.Template
	staticFS    fs.FS
	mux         *http.ServeMux
}

// NewServer wires everything together. It loads the store from disk, builds
// the participant registry, parses templates, registers routes, and seeds
// the demo data on first run.
func NewServer(cfg Config) (*Server, error) {
	store, err := OpenStore(cfg.StorePath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	bcast := NewBroadcaster(500)
	svc := bill.NewService(store, bcast)
	reg := NewRegistry()
	// Pre-create the server so we can use loadPersistedParticipants before
	// seeding defaults. This ensures user-added participants survive restarts
	// and seed only fills in missing defaults.
	s := &Server{
		cfg:         cfg,
		store:       store,
		svc:         svc,
		registry:    reg,
		broadcaster: bcast,
	}
	s.loadPersistedParticipants()
	if err := Seed(reg, svc); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	tmpls, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	staticFS, err := fs.Sub(webFS, "web/static")
	if err != nil {
		return nil, fmt.Errorf("static fs: %w", err)
	}
	s.templates = tmpls
	s.staticFS = staticFS
	s.mux = http.NewServeMux()
	s.routes()
	return s, nil
}

// Run starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.logging(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("gateway: listening on %s (store=%s)", s.cfg.Addr, s.store.Path())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// --- participant authorization -----------------------------------------------

// authorizeParticipantClaims checks that the caller has ADMIN authority
// covering every scope claim being granted. You can only give authority
// that you yourself hold — no privilege escalation.
//
// Each claim has the form "SEG1:SEG2:...:ROLE" or just "SEG1:SEG2:...".
// The caller needs ADMIN over the scope portion (everything before the
// role suffix). For example, granting "OPENDEMOCRACY:CORE:VOTER" requires
// ADMIN covering "OPENDEMOCRACY:CORE".
func (s *Server) authorizeParticipantClaims(caller *bill.Invoker, claims []string) error {
	for _, raw := range claims {
		scope := scopePortionOfClaim(raw)
		if !caller.HasAdminFor(scope) {
			return fmt.Errorf("you need ADMIN authority over %s to grant claim %q", scope, raw)
		}
	}
	return nil
}

// scopePortionOfClaim strips a trailing role token (ADMIN, PROPOSER, etc.)
// from a claim string and returns just the scope hierarchy. If the last
// segment is not a known role, the full string is returned as-is (it's a
// scope-only claim).
func scopePortionOfClaim(claim string) string {
	claim = strings.TrimSpace(strings.ToUpper(claim))
	parts := strings.Split(claim, ":")
	if len(parts) == 0 {
		return claim
	}
	last := parts[len(parts)-1]
	switch last {
	case "ADMIN", "PROPOSER", "EDITOR", "VOTER", "AUDITOR":
		return strings.Join(parts[:len(parts)-1], ":")
	}
	return claim
}

// --- participant persistence -------------------------------------------------
// Participants are stored alongside bills in the same PersistedStore using a
// "PARTICIPANT|{id}" key prefix. This way they survive restarts without
// adding a separate file.

// saveParticipant persists a participant to the store and adds it to the
// in-memory registry.
func (s *Server) saveParticipant(p Participant) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := s.store.Put(participantKeyPrefix+p.ID, data); err != nil {
		return err
	}
	s.registry.Add(p)
	return nil
}

// removeParticipant removes a participant from the store and registry.
func (s *Server) removeParticipant(id string) error {
	if !s.registry.Remove(id) {
		return errors.New("unknown participant: " + id)
	}
	// Remove from the store. Put an empty value (the store treats it as a
	// delete on next load since we filter empty values).
	return s.store.Put(participantKeyPrefix+id, []byte{})
}

// loadPersistedParticipants reads any participants from the store and adds
// them to the registry. Called during startup before seeding.
func (s *Server) loadPersistedParticipants() {
	kvs, err := s.store.ScanByPrefix(participantKeyPrefix)
	if err != nil {
		return
	}
	for _, kv := range kvs {
		if len(kv.Value) == 0 {
			continue
		}
		var p Participant
		if err := json.Unmarshal(kv.Value, &p); err != nil {
			continue
		}
		s.registry.Add(p)
	}
}

// electorateForScope counts how many registered participants have scope
// claims covering the given scope. This is the denominator for quorum and
// the source of ABSENCE at vote close time.
func (s *Server) electorateForScope(scope string) int {
	n := 0
	for _, p := range s.registry.List() {
		if p.Invoker().InScope(scope) {
			n++
		}
	}
	return n
}

// electorateForBill looks up the bill's scope and returns the electorate.
func (s *Server) electorateForBill(billID string) int {
	b, err := s.svc.GetBill(billID)
	if err != nil {
		return 0
	}
	return s.electorateForScope(b.Scope)
}

// electorateIDsForBill returns the list of participant IDs in scope for a
// bill. Used by EndVote for delegation resolution.
func (s *Server) electorateIDsForBill(billID string) []string {
	b, err := s.svc.GetBill(billID)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range s.registry.List() {
		if p.Invoker().InScope(b.Scope) {
			out = append(out, p.ID)
		}
	}
	return out
}

// callerFromRequest resolves the X-User header (or DefaultUser) into an
// *bill.Invoker via the participant registry. It is the gateway's stand-in
// for the X.509 certificate the chaincode would receive in a real Fabric
// deployment.
func (s *Server) callerFromRequest(r *http.Request) (Participant, *bill.Invoker, error) {
	id := strings.TrimSpace(r.Header.Get("X-User"))
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("as"))
	}
	if id == "" {
		id = s.cfg.DefaultUser
	}
	if id == "" {
		return Participant{}, nil, errors.New("no user specified (set X-User header or ?as= query param)")
	}
	p, err := s.registry.Get(id)
	if err != nil {
		return Participant{}, nil, err
	}
	return p, p.Invoker(), nil
}

// logging is a tiny request-logging middleware so the operator can see
// what's happening in `docker logs`.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lrw.status, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying ResponseWriter so SSE handlers can stream.
// Without this method, the embedded ResponseWriter's Flush is hidden by the
// wrapper struct and `w.(http.Flusher)` returns false.
func (l *loggingResponseWriter) Flush() {
	if f, ok := l.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// parseTemplates builds one *template.Template per dashboard page, each
// containing the shared layout plus that page's content. This is the
// idiomatic Go html/template way to do "extends layout".
func parseTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"formatTime": formatTime,
		"choiceName": choiceName,
		"roleNames":  roleNames,
		"isExecuted": func(s string) bool { return s == bill.StatusExecuted },
		"isRejected": func(s string) bool { return s == bill.StatusRejected },
		"isVoting":   func(s string) bool { return s == bill.StatusVoting },
		"isDraft":    func(s string) bool { return s == bill.StatusDraft },
		"slice": func(items ...string) []string { return items },
	}
	pages := []string{"index.html", "bill.html", "delegations.html", "petitions.html", "petition.html", "participants.html", "entities.html", "events.html"}
	out := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		t, err := template.New(p).Funcs(funcs).ParseFS(webFS,
			"web/templates/layout.html",
			"web/templates/"+p,
		)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		out[p] = t
	}
	// Partial templates (Turbo Stream fragments) parsed standalone, no layout.
	partials := []string{"_event_stream_item.html"}
	for _, p := range partials {
		t, err := template.New(p).Funcs(funcs).ParseFS(webFS, "web/templates/"+p)
		if err != nil {
			return nil, fmt.Errorf("parse partial %s: %w", p, err)
		}
		out[p] = t
	}
	return out, nil
}

// choiceName converts a Choice bitmask to a human-readable label for the
// dashboard. Multi-bit masks become pipe-joined.
func choiceName(c bill.Choice) string {
	parts := []string{}
	if c.Has(bill.ChoiceYes) {
		parts = append(parts, "YES")
	}
	if c.Has(bill.ChoiceNo) {
		parts = append(parts, "NO")
	}
	if c.Has(bill.ChoiceAbstain) {
		parts = append(parts, "ABSTAIN")
	}
	if c.Has(bill.ChoiceAbsence) {
		parts = append(parts, "ABSENCE")
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "|")
}

// roleNames converts a Role mask to a human-readable label.
func roleNames(r bill.Role) string {
	parts := []string{}
	if r.Has(bill.RoleProposer) {
		parts = append(parts, "PROPOSER")
	}
	if r.Has(bill.RoleEditor) {
		parts = append(parts, "EDITOR")
	}
	if r.Has(bill.RoleVoter) {
		parts = append(parts, "VOTER")
	}
	if r.Has(bill.RoleAuditor) {
		parts = append(parts, "AUDITOR")
	}
	if r.Has(bill.RoleAdmin) {
		parts = append(parts, "ADMIN")
	}
	if len(parts) == 0 {
		return "NONE"
	}
	return strings.Join(parts, "|")
}
