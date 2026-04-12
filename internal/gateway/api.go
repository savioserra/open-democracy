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
	ID                 string            `json:"id"`
	Owner              string            `json:"owner"`
	Status             string            `json:"status"`
	Quorum             float64           `json:"quorum"`
	ExecuteMask        string            `json:"executeMask"`
	RejectMask         string            `json:"rejectMask"`
	Scope              string            `json:"scope"`
	Versions           []versionDTO      `json:"versions"`
	Roles              map[string]string `json:"roles"`
	VoterCount         int               `json:"voterCount"`
	Votes              map[string]voteDTO `json:"votes"`
	VoteStart          int64             `json:"voteStart"`
	VoteEnd            int64             `json:"voteEnd"`
	AgreedVersionIndex int               `json:"agreedVersionIndex"`
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
	voterCount := 0
	for k, v := range b.Roles {
		roles[k] = roleNames(v)
		if v.Has(bill.RoleVoter) {
			voterCount++
		}
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
		VoterCount:         voterCount,
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
	electorate := s.electorateForBill(r.PathValue("id"))
	voteID, err := s.svc.VoteOnVersion(caller, time.Now().Unix(), r.PathValue("id"), r.PathValue("idx"), req.Choice, electorate)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"voteId": voteID})
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
	electorate := s.electorateForBill(r.PathValue("id"))
	if err := s.svc.SubmitBill(caller, r.PathValue("id"), req.StartTimeSeconds, req.DurationSeconds, electorate); err != nil {
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
	voteID, err := s.svc.CastVote(caller, time.Now().Unix(), r.PathValue("id"), req.Choice)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"voteId": voteID})
}

func (s *Server) handleAPIEndVote(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	electorateIDs := s.electorateIDsForBill(r.PathValue("id"))
	if err := s.svc.EndVote(caller, time.Now().Unix(), r.PathValue("id"), electorateIDs); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delegations ---------------------------------------------------------------

type delegationDTO struct {
	Delegator string `json:"delegator"`
	Delegatee string `json:"delegatee"`
	Scope     string `json:"scope"`
	Timestamp int64  `json:"timestamp"`
}

func (s *Server) handleAPIListDelegations(w http.ResponseWriter, r *http.Request) {
	delegations, err := s.svc.ListDelegations()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]delegationDTO, 0, len(delegations))
	for _, d := range delegations {
		out = append(out, delegationDTO{Delegator: d.Delegator, Delegatee: d.Delegatee, Scope: d.Scope, Timestamp: d.Timestamp})
	}
	writeJSON(w, http.StatusOK, out)
}

type delegateRequest struct {
	Delegatee string `json:"delegatee"`
	Scope     string `json:"scope"`
}

func (s *Server) handleAPIDelegate(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req delegateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.Delegate(caller, time.Now().Unix(), req.Delegatee, req.Scope); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAPIRevokeDelegation(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	if err := s.svc.RevokeDelegation(caller, r.PathValue("scope")); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Petitions -----------------------------------------------------------------

type petitionDTO struct {
	ID            string           `json:"id"`
	Initiator     string           `json:"initiator"`
	TargetScope   string           `json:"targetScope"`
	IPFSHash      string           `json:"ipfsHash"`
	Description   string           `json:"description"`
	Quorum        float64          `json:"quorum"`
	ExecuteMask   string           `json:"executeMask"`
	RejectMask    string           `json:"rejectMask"`
	Threshold     int              `json:"threshold"`
	Signatures    map[string]int64 `json:"signatures"`
	SignatureCount int             `json:"signatureCount"`
	Status        string           `json:"status"`
	CreatedBillID string           `json:"createdBillId,omitempty"`
	Timestamp     int64            `json:"timestamp"`
}

func toPetitionDTO(p *bill.Petition) petitionDTO {
	return petitionDTO{
		ID:             p.ID,
		Initiator:      p.Initiator,
		TargetScope:    p.TargetScope,
		IPFSHash:       p.IPFSHash,
		Description:    p.Description,
		Quorum:         p.Quorum,
		ExecuteMask:    choiceName(p.Criteria.ExecuteMask),
		RejectMask:     choiceName(p.Criteria.RejectMask),
		Threshold:      p.Threshold,
		Signatures:     p.Signatures,
		SignatureCount: len(p.Signatures),
		Status:         p.Status,
		CreatedBillID:  p.CreatedBillID,
		Timestamp:      p.Timestamp,
	}
}

func (s *Server) handleAPIListPetitions(w http.ResponseWriter, r *http.Request) {
	petitions, err := s.svc.ListPetitions()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]petitionDTO, 0, len(petitions))
	for _, p := range petitions {
		out = append(out, toPetitionDTO(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAPIGetPetition(w http.ResponseWriter, r *http.Request) {
	p, err := s.svc.GetPetition(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, toPetitionDTO(p))
}

type createPetitionRequest struct {
	ID          string `json:"id"`
	IPFSHash    string `json:"ipfsHash"`
	Description string `json:"description"`
	TargetScope string `json:"targetScope"`
	Quorum      string `json:"quorum"`
	ExecuteMask string `json:"executeMask"`
	RejectMask  string `json:"rejectMask"`
	Threshold   int    `json:"threshold"`
}

func (s *Server) handleAPICreatePetition(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req createPetitionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	q, err := parseQuorum(req.Quorum)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.svc.CreatePetition(caller, time.Now().Unix(), req.ID, req.IPFSHash, req.Description, req.TargetScope, q, req.ExecuteMask, req.RejectMask, req.Threshold); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	p, _ := s.svc.GetPetition(req.ID)
	writeJSON(w, http.StatusCreated, toPetitionDTO(p))
}

func (s *Server) handleAPISignPetition(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	eligible := s.eligibleVotersForScope(r.PathValue("id"))
	if err := s.svc.SignPetition(caller, time.Now().Unix(), r.PathValue("id"), eligible); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// eligibleVotersForScope returns all participant IDs whose scope covers the
// petition's target scope. This is the electorate for the auto-created bill.
func (s *Server) eligibleVotersForScope(petitionID string) []string {
	p, err := s.svc.GetPetition(petitionID)
	if err != nil {
		return nil
	}
	var out []string
	for _, part := range s.registry.List() {
		inv := part.Invoker()
		if inv.InScope(p.TargetScope) {
			out = append(out, part.ID)
		}
	}
	return out
}

// Vote verification ---------------------------------------------------------

func (s *Server) handleAPIVerifyVote(w http.ResponseWriter, r *http.Request) {
	receipt, err := s.svc.VerifyVote(r.PathValue("voteId"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"voteId":    receipt.VoteID,
		"billId":    receipt.BillID,
		"choice":    choiceName(receipt.Choice),
		"timestamp": receipt.Timestamp,
	})
}

// Participants & entities ---------------------------------------------------

func (s *Server) handleAPIListParticipants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.registry.List())
}

type createParticipantRequest struct {
	ID      string   `json:"id"`
	Display string   `json:"display"`
	Claims  []string `json:"claims"`
}

func (s *Server) handleAPICreateParticipant(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	var req createParticipantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if len(req.Claims) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("at least one scope claim is required"))
		return
	}
	if err := s.authorizeParticipantClaims(caller, req.Claims); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	p := Participant{ID: req.ID, Display: req.Display, Claims: req.Claims}
	if err := s.saveParticipant(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleAPIDeleteParticipant(w http.ResponseWriter, r *http.Request) {
	_, caller, err := s.callerFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	id := r.PathValue("id")
	target, tErr := s.registry.Get(id)
	if tErr != nil {
		writeErr(w, http.StatusNotFound, tErr)
		return
	}
	if err := s.authorizeParticipantClaims(caller, target.Claims); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	if err := s.removeParticipant(id); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// handleTurboStreamSSE serves a Server-Sent Events stream that emits
// <turbo-stream> HTML fragments. The dashboard's events page connects to
// this via <turbo-stream-source src="/api/events/turbo-stream">.
func (s *Server) handleTurboStreamSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
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
			writeTurboStreamEvent(w, s, ev)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeTurboStreamEvent(w http.ResponseWriter, s *Server, ev Event) {
	var buf strings.Builder
	if tmpl, ok := s.templates["_event_stream_item.html"]; ok {
		_ = tmpl.ExecuteTemplate(&buf, "event-stream-item", ev)
	}
	html := buf.String()
	// Each line of the SSE data field must be prefixed with "data: "
	fmt.Fprintf(w, "event: message\n")
	stream := fmt.Sprintf(`<turbo-stream action="prepend" target="event-list"><template>%s</template></turbo-stream>`, html)
	for _, line := range strings.Split(stream, "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprintf(w, "\n")
}
