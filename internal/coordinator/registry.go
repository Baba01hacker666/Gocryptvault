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
	mu             sync.RWMutex
	nodes          map[string]*RegisteredNode
	shardLocations map[string]map[string]string // fileID -> shardID -> nodeID
}

func NewRegistry() *Registry {
	return &Registry{
		nodes:          make(map[string]*RegisteredNode),
		shardLocations: make(map[string]map[string]string),
	}
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

func (r *Registry) GetNode(id string) *RegisteredNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nodes[id]
}

func (r *Registry) GetShardLocations(fileID string) map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	locs := make(map[string]string)
	if mapping, ok := r.shardLocations[fileID]; ok {
		for k, v := range mapping {
			locs[k] = v
		}
	}
	return locs
}

func (r *Registry) SetShardLocations(fileID string, mapping map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]string)
	for k, v := range mapping {
		m[k] = v
	}
	r.shardLocations[fileID] = m
}

func (r *Registry) DeleteShardLocations(fileID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.shardLocations, fileID)
}
