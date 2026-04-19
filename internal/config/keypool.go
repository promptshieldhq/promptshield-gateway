package config

import (
	"strings"
	"sync/atomic"
)

// KeyPool rotates API keys in round-robin order.
type KeyPool struct {
	keys    []string
	counter atomic.Uint64
}

func NewKeyPool(raw string) *KeyPool {
	parts := strings.Split(raw, ",")
	keys := make([]string, 0, len(parts))
	for _, k := range parts {
		if k := strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	return &KeyPool{keys: keys}
}

func (p *KeyPool) Len() int { return len(p.keys) }

// Pick returns the next key, or "" if empty.
func (p *KeyPool) Pick() string {
	if len(p.keys) == 0 {
		return ""
	}
	idx := p.counter.Add(1) - 1
	return p.keys[idx%uint64(len(p.keys))]
}
