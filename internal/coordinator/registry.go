package coordinator

import (
	"sort"
	"sync"
	"time"
)

type RegisteredNode struct {
	ID            string
	Endpoint      string
	CapacityBytes int64
	LastSeen      time.Time
}

type Registry struct {
	mu    sync.RWMutex
	nodes map[string]*RegisteredNode
}

func NewRegistry() *Registry {
	return &Registry{nodes: make(map[string]*RegisteredNode)}
}

func (r *Registry) Register(id, endpoint string, capacity int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes[id] = &RegisteredNode{
		ID:            id,
		Endpoint:      endpoint,
		CapacityBytes: capacity,
		LastSeen:      time.Now(),
	}
}

func (r *Registry) GetHealthyNodes() []*RegisteredNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var healthy []*RegisteredNode
	for _, n := range r.nodes {
		if time.Since(n.LastSeen) < 5*time.Minute {
			healthy = append(healthy, n)
		}
	}
	sort.Slice(healthy, func(i, j int) bool {
		return healthy[i].ID < healthy[j].ID
	})
	return healthy
}
