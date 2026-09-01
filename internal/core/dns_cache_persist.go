package core

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/NikKuz99/turnguard/internal/util"
)

// Persistent DNS cache — stores resolved IPs between restarts.
// Same concept as Android's dns_cache_persist.go.

const (
	persistSaveInterval = 60 * time.Second
	persistMaxIPsPerDomain = 30
)

type persistMetric struct {
	IP          string  `json:"ip"`
	RTTms       int64   `json:"rtt_ms"`
	SuccessRate float64 `json:"success_rate"`
	LastSeen    string  `json:"last_seen"`
	FailCount   int     `json:"fail_count"`
	TotalTries  int     `json:"total_tries"`
	TotalOK     int     `json:"total_ok"`
}

type persistDomain struct {
	IPs     []string         `json:"ips"`
	Metrics []persistMetric  `json:"metrics,omitempty"`
}

type persistFile struct {
	Version int                      `json:"version"`
	SavedAt string                   `json:"saved_at"`
	Domains map[string]persistDomain `json:"domains"`
}

type PersistentCache struct {
	mu      sync.Mutex
	path    string
	loaded  bool
	dirty   bool
	stopCh  chan struct{}
	stopped bool
	wg      sync.WaitGroup
}

var Persist = &PersistentCache{
	stopCh: make(chan struct{}),
}

func (p *PersistentCache) SetCachePath(path string) {
	if path == "" {
		return
	}
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()

	if err := p.Load(); err != nil {
		util.TurnLog("[DNSCache] load error: %v", err)
	} else {
		util.TurnLog("[DNSCache] loaded cache from %s", path)
	}
	p.startSaver()
}

func (p *PersistentCache) Load() error {
	p.mu.Lock()
	path := p.path
	p.mu.Unlock()
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var pf persistFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return err
	}
	if pf.Version != 1 {
		return nil
	}

	// Merge into hostCache
	hostCache.mu.Lock()
	for domain, dd := range pf.Domains {
		if len(dd.IPs) == 0 {
			continue
		}
		existing := hostCache.allIps[domain]
		merged := mergeUnique(existing, dd.IPs)
		if len(merged) > persistMaxIPsPerDomain {
			merged = merged[:persistMaxIPsPerDomain]
		}
		hostCache.allIps[domain] = merged
		if len(merged) > 0 {
			hostCache.ips[domain] = merged[0]
		}
	}
	hostCache.mu.Unlock()

	// Merge into vkHosts dynamic + metrics
	vkHosts.mu.Lock()
	for domain, dd := range pf.Domains {
		if len(dd.IPs) > 0 {
			old := vkHosts.dynamic[domain]
			merged := mergeUnique(old, dd.IPs)
			if len(merged) > persistMaxIPsPerDomain {
				merged = merged[:persistMaxIPsPerDomain]
			}
			vkHosts.dynamic[domain] = merged
		}
		for _, dm := range dd.Metrics {
			key := metricKey(domain, dm.IP)
			lastSeen, _ := time.Parse(time.RFC3339, dm.LastSeen)
			if lastSeen.IsZero() {
				lastSeen = time.Now()
			}
			vkHosts.metrics[key] = &HostMetric{
				IP:          dm.IP,
				RTT:         time.Duration(dm.RTTms) * time.Millisecond,
				SuccessRate: dm.SuccessRate,
				LastSeen:    lastSeen,
				FailCount:   dm.FailCount,
				TotalTries:  dm.TotalTries,
				TotalOK:     dm.TotalOK,
			}
		}
	}
	vkHosts.mu.Unlock()

	util.TurnLog("[DNSCache] loaded %d domains from disk", len(pf.Domains))
	return nil
}

func (p *PersistentCache) MarkDirty() {
	p.mu.Lock()
	p.dirty = true
	p.mu.Unlock()
}

func (p *PersistentCache) SaveNow() {
	if err := p.save(); err != nil {
		util.TurnLog("[DNSCache] save error: %v", err)
	}
}

func (p *PersistentCache) save() error {
	p.mu.Lock()
	path := p.path
	p.dirty = false
	p.mu.Unlock()
	if path == "" {
		return nil
	}

	pf := persistFile{
		Version: 1,
		SavedAt: time.Now().Format(time.RFC3339),
		Domains: make(map[string]persistDomain),
	}

	// Collect all known domains
	domains := make(map[string]struct{})
	hostCache.mu.RLock()
	for d := range hostCache.allIps {
		domains[d] = struct{}{}
	}
	for d := range hostCache.ips {
		domains[d] = struct{}{}
	}
	hostCache.mu.RUnlock()

	vkHosts.mu.RLock()
	for d := range vkHosts.dynamic {
		domains[d] = struct{}{}
	}
	// Snapshot metrics
	metricsSnapshot := make(map[string]*HostMetric, len(vkHosts.metrics))
	for k, v := range vkHosts.metrics {
		metricsSnapshot[k] = v
	}
	vkHosts.mu.RUnlock()

	for domain := range domains {
		hostCache.mu.RLock()
		allIps := append([]string(nil), hostCache.allIps[domain]...)
		hostCache.mu.RUnlock()

		vkHosts.mu.RLock()
		dynIps := vkHosts.dynamic[domain]
		vkHosts.mu.RUnlock()

		mergedIPs := mergeUnique(allIps, dynIps)
		// Also include IPs from metrics
		prefix := domain + ":"
		for k := range metricsSnapshot {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				ip := k[len(prefix):]
				mergedIPs = mergeUnique(mergedIPs, []string{ip})
			}
		}

		if len(mergedIPs) == 0 {
			continue
		}

		var dms []persistMetric
		vkHosts.mu.RLock()
		for _, ip := range mergedIPs {
			key := metricKey(domain, ip)
			m, ok := vkHosts.metrics[key]
			if !ok {
				continue
			}
			dms = append(dms, persistMetric{
				IP:          m.IP,
				RTTms:       m.RTT.Milliseconds(),
				SuccessRate: m.SuccessRate,
				LastSeen:    m.LastSeen.Format(time.RFC3339),
				FailCount:   m.FailCount,
				TotalTries:  m.TotalTries,
				TotalOK:     m.TotalOK,
			})
		}
		vkHosts.mu.RUnlock()

		pf.Domains[domain] = persistDomain{
			IPs:     mergedIPs,
			Metrics: dms,
		}
	}

	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (p *PersistentCache) startSaver() {
	p.mu.Lock()
	if !p.stopped {
		close(p.stopCh)
	}
	p.stopCh = make(chan struct{})
	p.stopped = false
	p.mu.Unlock()

	p.wg.Add(1)
	go func(stopCh <-chan struct{}) {
		defer p.wg.Done()
		ticker := time.NewTicker(persistSaveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				_ = p.save()
				return
			case <-ticker.C:
				p.mu.Lock()
				dirty := p.dirty
				p.mu.Unlock()
				if dirty {
					_ = p.save()
				}
			}
		}
	}(p.stopCh)
}

func (p *PersistentCache) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return
	}
	p.stopped = true
	close(p.stopCh)
	p.wg.Wait()
}
