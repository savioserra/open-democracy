package gateway

import "net/http"

// routes wires every URL pattern to its handler. Routes are grouped into
// dashboard pages (HTML), REST API endpoints (JSON), and the SSE stream.
//
// The Go 1.22 ServeMux pattern syntax (`METHOD /path/{var}`) is used so we
// don't need a third-party router for a small surface like this.
func (s *Server) routes() {
	// Dashboard pages
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /bills/{id}", s.handleBillPage)
	s.mux.HandleFunc("GET /participants", s.handleParticipantsPage)
	s.mux.HandleFunc("GET /entities", s.handleEntitiesPage)
	s.mux.HandleFunc("GET /events", s.handleEventsPage)

	s.mux.HandleFunc("GET /delegations", s.handleDelegationsPage)

	s.mux.HandleFunc("GET /petitions", s.handlePetitionsPage)
	s.mux.HandleFunc("GET /petitions/{id}", s.handlePetitionPage)

	// HTML form actions (the dashboard posts plain forms; we redirect back).
	s.mux.HandleFunc("POST /actions/add-participant", s.handleFormAddParticipant)
	s.mux.HandleFunc("POST /actions/remove-participant", s.handleFormRemoveParticipant)
	s.mux.HandleFunc("POST /actions/delegate", s.handleFormDelegate)
	s.mux.HandleFunc("POST /actions/revoke-delegation", s.handleFormRevokeDelegation)
	s.mux.HandleFunc("POST /actions/create-petition", s.handleFormCreatePetition)
	s.mux.HandleFunc("POST /actions/sign-petition", s.handleFormSignPetition)
	s.mux.HandleFunc("POST /actions/create-bill", s.handleFormCreateBill)
	s.mux.HandleFunc("POST /actions/edit-bill", s.handleFormEditBill)
	s.mux.HandleFunc("POST /actions/assign-role", s.handleFormAssignRole)
	s.mux.HandleFunc("POST /actions/version-vote", s.handleFormVersionVote)
	s.mux.HandleFunc("POST /actions/submit-bill", s.handleFormSubmitBill)
	s.mux.HandleFunc("POST /actions/cast-vote", s.handleFormCastVote)
	s.mux.HandleFunc("POST /actions/end-vote", s.handleFormEndVote)

	// REST API
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/bills", s.handleAPIListBills)
	s.mux.HandleFunc("POST /api/bills", s.handleAPICreateBill)
	s.mux.HandleFunc("GET /api/bills/{id}", s.handleAPIGetBill)
	s.mux.HandleFunc("POST /api/bills/{id}/versions", s.handleAPIEditBill)
	s.mux.HandleFunc("POST /api/bills/{id}/versions/{idx}/votes", s.handleAPIVersionVote)
	s.mux.HandleFunc("POST /api/bills/{id}/roles", s.handleAPIAssignRole)
	s.mux.HandleFunc("POST /api/bills/{id}/submit", s.handleAPISubmit)
	s.mux.HandleFunc("POST /api/bills/{id}/votes", s.handleAPICastVote)
	s.mux.HandleFunc("POST /api/bills/{id}/end", s.handleAPIEndVote)
	s.mux.HandleFunc("GET /api/delegations", s.handleAPIListDelegations)
	s.mux.HandleFunc("POST /api/delegations", s.handleAPIDelegate)
	s.mux.HandleFunc("DELETE /api/delegations/{user}/{scope}", s.handleAPIRevokeDelegation)
	s.mux.HandleFunc("GET /api/petitions", s.handleAPIListPetitions)
	s.mux.HandleFunc("POST /api/petitions", s.handleAPICreatePetition)
	s.mux.HandleFunc("GET /api/petitions/{id}", s.handleAPIGetPetition)
	s.mux.HandleFunc("POST /api/petitions/{id}/sign", s.handleAPISignPetition)
	s.mux.HandleFunc("GET /api/votes/{voteId}", s.handleAPIVerifyVote)
	s.mux.HandleFunc("GET /api/participants", s.handleAPIListParticipants)
	s.mux.HandleFunc("POST /api/participants", s.handleAPICreateParticipant)
	s.mux.HandleFunc("DELETE /api/participants/{id}", s.handleAPIDeleteParticipant)
	s.mux.HandleFunc("GET /api/entities", s.handleAPIListEntities)
	s.mux.HandleFunc("GET /api/events", s.handleAPIEventsHistory)

	// Server-sent events
	s.mux.HandleFunc("GET /api/events/stream", s.handleSSE)
	s.mux.HandleFunc("GET /api/events/turbo-stream", s.handleTurboStreamSSE)

	// Static assets (CSS)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.staticFS)))
}
