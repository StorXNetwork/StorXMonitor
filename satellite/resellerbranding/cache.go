// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package resellerbranding

import (
	"net"
	"strings"
	"sync"
	"time"
)

// HostCache caches branding JSON payloads keyed by request host.
type HostCache struct {
	mu      sync.RWMutex
	entries map[string]hostCacheEntry
	ttl     time.Duration
}

type hostCacheEntry struct {
	payload   []byte
	expiresAt time.Time
}

// DefaultHostCache is retained for tests; console branding reads from DB on every request.
var DefaultHostCache = NewHostCache(2 * time.Hour)

// NewHostCache creates a host-keyed branding cache with the given TTL.
func NewHostCache(ttl time.Duration) *HostCache {
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	return &HostCache{
		entries: make(map[string]hostCacheEntry),
		ttl:     ttl,
	}
}

// Get returns a cached branding payload for host when present and not expired.
func (c *HostCache) Get(host string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	host = NormalizeHost(host)
	if host == "" {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			c.Delete(host)
		}
		return nil, false
	}
	return entry.payload, true
}

// Set stores a branding payload for host until TTL expires.
func (c *HostCache) Set(host string, payload []byte) {
	if c == nil || len(payload) == 0 {
		return
	}
	host = NormalizeHost(host)
	if host == "" {
		return
	}

	c.mu.Lock()
	c.entries[host] = hostCacheEntry{
		payload:   append([]byte(nil), payload...),
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Delete removes a cached branding payload for host.
func (c *HostCache) Delete(host string) {
	if c == nil {
		return
	}
	host = NormalizeHost(host)
	if host == "" {
		return
	}

	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// NormalizeHost lowercases a host header value and strips any port suffix.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
