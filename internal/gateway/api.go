package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"open-democracy/chaincode/bill"
)

// Standard JSON helpers ------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// Health ---------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"time":         time.Now().UTC().Format(time.RFC3339),
		"participants": len(s.registry.List()),
	})
}

// Bills ----------------------------------------------------------------------

// billDTO mirrors bill.Bill but renders Choice as a string for the dashboard
// and external API consumers, who shouldn't have to know about the bitmask
// encoding. The internal *bill.Bill is preserved as-is on disk.
type billDTO struct {
	ID                 string         `json:"id"`
	Owner              string         `json:"owner"`
	Status             string         `json:"status"`
	Quorum             float64        `json:"quorum"`
	ExecuteMask        string         `json:"executeMask"`
	RejectMask         string         `json:"rejectMask"`
	Scope              string         `json:"scope"`
	Versions           []versionDTO   `json:"versions"`
	Roles              map[string]string `json:"roles"`
	Votes              map[string]voteDTO `json:"votes"`
	VoteStart          int64          `json:"voteStart"`
	VoteEnd            int64          `json:"voteEnd"`
	AgreedVersionIndex int            `json:"agreedVersionIndex"`
}

type versionDTO struct {
	IPFSHash    string             `json:"ipfsHash"`
	Description string             `json:"description"`
	Timestamp   int64              `json:"timestamp"`
	Editor      string             `json:"editor"`
	Votes       map[string]voteDTO `json:"votes"`
}

type voteDTO struct {
	VoterID   string `json:"voterId"`
	Choice    string `json:"choice"`
	Timestamp int64  `json:"timestamp"`
}

func toBillDTO(b *bill.Bill) billDTO {
	roles := map[string]string{}
	for k, v := range b.Roles {
		roles[k] = roleNames(v)
	}
	votes := map[string]voteDTO{}
	for k, v := range b.Votes {
		votes[k] = voteDTO{VoterID: v.VoterID, Choice: choiceName(v.Choice), Timestamp: v.Timestamp}
	}
	versions := make([]versionDTO, 0, len(b.Versions))
	for _, v := range b.Versions {
		vv := map[string]voteDTO{}
		for k, vote := range v.Votes {
			vv[k] = voteDTO{VoterID: vote.VoterID, Choice: choiceName(vote.Choice), Timestamp: vote.Timestamp}
		}
		versions = append(versions, versionDTO{
			IPFSHash:    v.IPFSHash,
			Description: v.Description,
			Timestamp:   v.Timestamp,
			Editor:      v.Editor,
			Votes:       vv,
		})
	}
	return billDTO{
		ID:                 b.ID,
		Owner:              b.Owner,
		Status:             b.Status,
		Quorum:             b.Quorum,
		ExecuteMask:        choiceName(b.Criteria.ExecuteMask),
		RejectMask:         choiceName(b.Criteria.RejectMask),
		Scope:              b.Scope,
		Versions:           versions,
		Roles:              roles,
		Votes:              votes,
		VoteStart:          b.VoteStart,
		VoteEnd:            b.VoteEnd,
		AgreedVersionIndex: b.AgreedVersionIndex,
	}
}

func (s *Server) handleAPIListBills(w http.ResponseWriter, r *http.Request) {
	bills, err := s.svc.ListBills()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]billDTO, 0, len(bills))
	for _, b := range bills {
		out = append(out, toBillDTO(b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAPIGetBill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	b, err := s.svc.GetBill(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, toBillDTO(b))
}

// createBillRequest is the JSON payload accepted by POST /api/bills.
type createBillRequest struct {
	ID          string `json:"id"`
	IPFSHash    string `json:"ipfsHash"`
	Description string `json:"description"`
	Quorum      string `json:"quorum"`
	Scope       string `json:"scope"`
	ExecuteMask string `json:"executeMask"`
	RejectMask  string `json:"rejectMask"`
}

func (s *Server) handleAPICreateBill(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req createBillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	q, err := parseQuorum(req.Quorum)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.CreateBill(caller, time.Now().Unix(), req.ID, req.IPFSHash, req.Description, q, req.Scope, req.ExecuteMask, req.RejectMask); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	b, err := s.svc.GetBill(req.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, toBillDTO(b))
}

type editBillRequest struct {
	IPFSHash    string `json:"ipfsHash"`
	Description string `json:"description"`
}

func (s *Server) handleAPIEditBill(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req editBillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	id := r.PathValue("id")
	if err := s.svc.EditBill(caller, time.Now().Unix(), id, req.IPFSHash, req.Description); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	b, err := s.svc.GetBill(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, toBillDTO(b))
}

type assignRoleRequest struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

func (s *Server) handleAPIAssignRole(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req assignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.AssignRoleForBill(caller, r.PathValue("id"), req.UserID, req.Role); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type voteRequest struct {
	Choice string `json:"choice"`
}

func (s *Server) handleAPIVersionVote(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req voteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.VoteOnVersion(caller, time.Now().Unix(), r.PathValue("id"), r.PathValue("idx"), req.Choice); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type submitBillRequest struct {
	StartTimeSeconds string `json:"startTimeSeconds"`
	DurationSeconds  string `json:"durationSeconds"`
}

func (s *Server) handleAPISubmit(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req submitBillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.StartTimeSeconds) == "" {
		req.StartTimeSeconds = strconv.FormatInt(time.Now().Unix(), 10)
	}
	if err := s.svc.SubmitBill(caller, r.PathValue("id"), req.StartTimeSeconds, req.DurationSeconds); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAPICastVote(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req voteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.CastVote(caller, time.Now().Unix(), r.PathValue("id"), req.Choice); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAPIEndVote(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	if err := s.svc.EndVote(caller, time.Now().Unix(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Participants & entities ---------------------------------------------------

func (s *Server) handleAPIListParticipants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.registry.List())
}

// Entity is a top-level scope segment with the participants and bills under
// it. The dashboard groups federated state this way to give an at-a-glance
// view of the polity.
type Entity struct {
	Name         string   `json:"name"`
	BillIDs      []string `json:"billIds"`
	Participants []string `json:"participants"`
}

func (s *Server) collectEntities() ([]Entity, error) {
	bills, err := s.svc.ListBills()
	if err != nil {
		return nil, err
	}
	byName := map[string]*Entity{}
	getOrCreate := func(name string) *Entity {
		if name == "" {
			return nil
		}
		e, ok := byName[name]
		if !ok {
			e = &Entity{Name: name}
			byName[name] = e
		}
		return e
	}
	for _, b := range bills {
		seg := topScopeSegment(b.Scope)
		e := getOrCreate(seg)
		if e == nil {
			continue
		}
		e.BillIDs = append(e.BillIDs, b.ID)
	}
	for _, p := range s.registry.List() {
		seen := map[string]bool{}
		for _, c := range p.Claims {
			seg := topScopeSegment(c)
			if seg == "" || seen[seg] {
				continue
			}
			seen[seg] = true
			e := getOrCreate(seg)
			if e == nil {
				continue
			}
			e.Participants = append(e.Participants, p.ID)
		}
	}
	out := make([]Entity, 0, len(byName))
	for _, e := range byName {
		sort.Strings(e.BillIDs)
		sort.Strings(e.Participants)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Server) handleAPIListEntities(w http.ResponseWriter, r *http.Request) {
	out, err := s.collectEntities()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func topScopeSegment(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ":")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "*" {
			continue
		}
		// strip role suffix if present at the very top (rare)
		return p
	}
	return ""
}

// Events ---------------------------------------------------------------------

func (s *Server) handleAPIEventsHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.broadcaster.History())
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Replay history first so a fresh subscriber sees recent state.
	for _, ev := range s.broadcaster.History() {
		writeSSE(w, ev)
	}
	flusher.Flush()

	ch := s.broadcaster.Subscribe()
	defer s.broadcaster.Unsubscribe(ch)

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, ev)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev Event) {
	data, _ := json.Marshal(ev)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Name, data)
}
