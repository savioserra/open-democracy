package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"open-democracy/chaincode/bill"
)

// pageData is the common envelope passed to every dashboard template. It
// carries enough state for the layout (active nav, current "as" user) plus
// page-specific Data.
type pageData struct {
	Title    string
	Active   string
	Users    []Participant
	AsUser   string
	Flash    string
	FlashErr string
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	if data.AsUser == "" {
		if cur := strings.TrimSpace(r.URL.Query().Get("as")); cur != "" {
			data.AsUser = cur
		} else {
			data.AsUser = s.cfg.DefaultUser
		}
	}
	data.Users = s.registry.List()
	if data.Flash == "" {
		data.Flash = r.URL.Query().Get("flash")
	}
	if data.FlashErr == "" {
		data.FlashErr = r.URL.Query().Get("err")
	}
	tmpl, ok := s.templates[name]
	if !ok {
		http.Error(w, "no such template: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index page: list of bills with high-level state.
type indexData struct {
	Bills []billDTO
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	bills, err := s.svc.ListBills()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]billDTO, 0, len(bills))
	for _, b := range bills {
		out = append(out, toBillDTO(b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	s.render(w, r, "index.html", pageData{
		Title:  "Bills",
		Active: "bills",
		Data:   indexData{Bills: out},
	})
}

// Bill detail page.
type billPageData struct {
	Bill billDTO
	// Eligible voters lists every participant the dashboard knows about
	// who could (according to scope+role) be granted votes for this bill.
	EligibleParticipants []Participant
}

func (s *Server) handleBillPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	b, err := s.svc.GetBill(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dto := toBillDTO(b)
	all := s.registry.List()
	eligible := make([]Participant, 0, len(all))
	for _, p := range all {
		inv := p.Invoker()
		if inv.InScope(b.Scope) {
			eligible = append(eligible, p)
		}
	}
	s.render(w, r, "bill.html", pageData{
		Title:  "Bill " + id,
		Active: "bills",
		Data:   billPageData{Bill: dto, EligibleParticipants: eligible},
	})
}

// Petitions page: list all petitions.
func (s *Server) handlePetitionsPage(w http.ResponseWriter, r *http.Request) {
	petitions, err := s.svc.ListPetitions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]petitionDTO, 0, len(petitions))
	for _, p := range petitions {
		out = append(out, toPetitionDTO(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	s.render(w, r, "petitions.html", pageData{
		Title:  "Petitions",
		Active: "petitions",
		Data:   out,
	})
}

// Petition detail page.
type petitionPageData struct {
	Petition    petitionDTO
	Participants []Participant
	HasSigned   bool
}

func (s *Server) handlePetitionPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.svc.GetPetition(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dto := toPetitionDTO(p)
	// Determine if current user already signed.
	asUser := strings.TrimSpace(r.URL.Query().Get("as"))
	if asUser == "" {
		asUser = s.cfg.DefaultUser
	}
	_, hasSigned := p.Signatures[asUser]
	s.render(w, r, "petition.html", pageData{
		Title:  "Petition " + id,
		Active: "petitions",
		Data:   petitionPageData{Petition: dto, Participants: s.registry.List(), HasSigned: hasSigned},
	})
}

// Participants page.
func (s *Server) handleParticipantsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "participants.html", pageData{
		Title:  "Participants",
		Active: "participants",
		Data:   s.registry.List(),
	})
}

// Entities page.
func (s *Server) handleEntitiesPage(w http.ResponseWriter, r *http.Request) {
	ents, err := s.collectEntities()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "entities.html", pageData{
		Title:  "Entities",
		Active: "entities",
		Data:   ents,
	})
}

// Events page (history + SSE link).
func (s *Server) handleEventsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "events.html", pageData{
		Title:  "Events",
		Active: "events",
		Data:   s.broadcaster.History(),
	})
}

// Form action handlers ------------------------------------------------------

// callerForForm resolves the caller from the form's _user field, falling
// back to the X-User header / default user.
func (s *Server) callerForForm(r *http.Request) (Participant, *bill.Invoker, error) {
	if id := strings.TrimSpace(r.FormValue("_user")); id != "" {
		p, err := s.registry.Get(id)
		if err != nil {
			return Participant{}, nil, err
		}
		return p, p.Invoker(), nil
	}
	return s.callerFromRequest(r)
}

func (s *Server) redirectAfterAction(w http.ResponseWriter, r *http.Request, target string, err error) {
	q := url.Values{}
	if err != nil {
		q.Set("err", err.Error())
	} else {
		q.Set("flash", "ok")
	}
	if as := r.FormValue("_user"); as != "" {
		q.Set("as", as)
	} else if as := r.URL.Query().Get("as"); as != "" {
		q.Set("as", as)
	}
	http.Redirect(w, r, target+"?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) handleFormCreateBill(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/", err)
		return
	}
	q, err := parseQuorum(r.FormValue("quorum"))
	if err != nil {
		s.redirectAfterAction(w, r, "/", err)
		return
	}
	err = s.svc.CreateBill(caller, time.Now().Unix(),
		r.FormValue("id"),
		r.FormValue("ipfsHash"),
		r.FormValue("description"),
		q,
		r.FormValue("scope"),
		r.FormValue("executeMask"),
		r.FormValue("rejectMask"),
	)
	target := "/"
	if err == nil {
		target = "/bills/" + r.FormValue("id")
	}
	s.redirectAfterAction(w, r, target, err)
}

func (s *Server) handleFormEditBill(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, caller, err := s.callerForForm(r)
	id := r.FormValue("billId")
	if err != nil {
		s.redirectAfterAction(w, r, "/bills/"+id, err)
		return
	}
	err = s.svc.EditBill(caller, time.Now().Unix(), id, r.FormValue("ipfsHash"), r.FormValue("description"))
	s.redirectAfterAction(w, r, "/bills/"+id, err)
}

func (s *Server) handleFormAssignRole(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("billId")
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/bills/"+id, err)
		return
	}
	err = s.svc.AssignRoleForBill(caller, id, r.FormValue("userId"), r.FormValue("role"))
	s.redirectAfterAction(w, r, "/bills/"+id, err)
}

func (s *Server) handleFormVersionVote(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("billId")
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/bills/"+id, err)
		return
	}
	err = s.svc.VoteOnVersion(caller, time.Now().Unix(), id, r.FormValue("versionIndex"), r.FormValue("choice"))
	s.redirectAfterAction(w, r, "/bills/"+id, err)
}

func (s *Server) handleFormSubmitBill(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("billId")
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/bills/"+id, err)
		return
	}
	start := r.FormValue("startTime")
	if strings.TrimSpace(start) == "" {
		start = fmt.Sprintf("%d", time.Now().Unix())
	}
	err = s.svc.SubmitBill(caller, id, start, r.FormValue("duration"))
	s.redirectAfterAction(w, r, "/bills/"+id, err)
}

func (s *Server) handleFormCastVote(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("billId")
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/bills/"+id, err)
		return
	}
	err = s.svc.CastVote(caller, time.Now().Unix(), id, r.FormValue("choice"))
	s.redirectAfterAction(w, r, "/bills/"+id, err)
}

func (s *Server) handleFormEndVote(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("billId")
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/bills/"+id, err)
		return
	}
	err = s.svc.EndVote(caller, time.Now().Unix(), id)
	s.redirectAfterAction(w, r, "/bills/"+id, err)
}

func (s *Server) handleFormCreatePetition(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/petitions", err)
		return
	}
	q, err := parseQuorum(r.FormValue("quorum"))
	if err != nil {
		s.redirectAfterAction(w, r, "/petitions", err)
		return
	}
	threshold := 3
	if v := r.FormValue("threshold"); v != "" {
		if t, e := strconv.Atoi(v); e == nil && t > 0 {
			threshold = t
		}
	}
	petID := r.FormValue("id")
	err = s.svc.CreatePetition(caller, time.Now().Unix(),
		petID, r.FormValue("ipfsHash"), r.FormValue("description"),
		r.FormValue("targetScope"), q, r.FormValue("executeMask"), r.FormValue("rejectMask"), threshold,
	)
	target := "/petitions"
	if err == nil {
		target = "/petitions/" + petID
	}
	s.redirectAfterAction(w, r, target, err)
}

func (s *Server) handleFormSignPetition(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	petID := r.FormValue("petitionId")
	_, caller, err := s.callerForForm(r)
	if err != nil {
		s.redirectAfterAction(w, r, "/petitions/"+petID, err)
		return
	}
	eligible := s.eligibleVotersForScope(petID)
	err = s.svc.SignPetition(caller, time.Now().Unix(), petID, eligible)
	s.redirectAfterAction(w, r, "/petitions/"+petID, err)
}
