package rest

import (
	"encoding/json"
	"net/http"

	"github.com/Baba01hacker666/Gocryptvault/internal/coordinator"
)

// RESTHandler wraps the coordinator server logic to serve it over HTTPS
type RESTHandler struct {
	coord *coordinator.CoordinatorServer
	mux   *http.ServeMux
}

func NewRESTHandler(coord *coordinator.CoordinatorServer) *RESTHandler {
	h := &RESTHandler{
		coord: coord,
		mux:   http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

func (h *RESTHandler) registerRoutes() {
	h.mux.HandleFunc("/api/v1/health", h.handleHealth)
	// Additional routes for RegisterNode, Heartbeat, UploadPlan etc.
}

func (h *RESTHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "coordinator"})
}

func (h *RESTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
