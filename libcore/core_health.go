package libcore

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	coreHealthTTL         = 6 * time.Hour
	coreHealthMaxEntries  = 256
	coreHalfOpenProbeWait = 20 * time.Second
)

type coreHealthEntry struct {
	routeHealth
	HalfOpenProbeAtMs int64
}

type coreTelemetrySnapshot struct {
	NetworkScope     string        `json:"network_scope"`
	SelectedOutbound string        `json:"selected_outbound"`
	LastDecision     string        `json:"last_decision"`
	RouteCount       int           `json:"route_count"`
	OpenCircuitCount int           `json:"open_circuit_count"`
	Adaptive         adaptiveState `json:"adaptive"`
	UpdatedAtMs      int64         `json:"updated_at_ms"`
}

type coreHealthSnapshot struct {
	Key             string `json:"key"`
	LastScore       int32  `json:"last_score"`
	LatencyEWMA     int32  `json:"latency_ewma"`
	JitterEWMA      int32  `json:"jitter_ewma"`
	SuccessStreak   int    `json:"success_streak"`
	FailStreak      int    `json:"fail_streak"`
	BlockUntilMs    int64  `json:"block_until_ms"`
	HalfOpenProbeAt int64  `json:"half_open_probe_at_ms"`
	LastUpdatedMs   int64  `json:"last_updated_ms"`
}

type coreHealthManager struct {
	lock             sync.Mutex
	routes           map[string]coreHealthEntry
	networkScope     string
	selectedOutbound string
	lastDecision     string
	lastCleanupAtMs  int64
	updatedAtMs      int64
}

var healthManager = coreHealthManager{routes: map[string]coreHealthEntry{}}

func currentNetworkScope() string {
	if intfBox == nil {
		return "network:unknown"
	}
	state := strings.TrimSpace(intfBox.WIFIState())
	if state == "" || state == "," || strings.Contains(strings.ToLower(state), "<unknown") {
		return "network:mobile"
	}
	return "network:wifi:" + state
}

func (m *coreHealthManager) syncNetworkScope(nowMs int64) string {
	scope := currentNetworkScope()
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.networkScope != scope {
		m.networkScope = scope
		m.lastDecision = "network_changed:" + scope
		m.updatedAtMs = nowMs
	}
	return scope
}

func (m *coreHealthManager) routeKey(base string, nowMs int64) string {
	return m.syncNetworkScope(nowMs) + "|" + base
}

func (m *coreHealthManager) cleanupLocked(nowMs int64) {
	if nowMs-m.lastCleanupAtMs < int64(time.Minute) && len(m.routes) <= coreHealthMaxEntries {
		return
	}
	m.lastCleanupAtMs = nowMs
	cutoff := nowMs - coreHealthTTL.Milliseconds()
	for key, entry := range m.routes {
		if entry.LastUpdatedMs < cutoff {
			delete(m.routes, key)
		}
	}
	for len(m.routes) > coreHealthMaxEntries {
		type kv struct {
			key   string
			entry coreHealthEntry
		}
		items := make([]kv, 0, len(m.routes))
		for key, entry := range m.routes {
			items = append(items, kv{key: key, entry: entry})
		}
		slices.SortFunc(items, func(a, b kv) int {
			switch {
			case a.entry.LastUpdatedMs < b.entry.LastUpdatedMs:
				return -1
			case a.entry.LastUpdatedMs > b.entry.LastUpdatedMs:
				return 1
			case a.key < b.key:
				return -1
			case a.key > b.key:
				return 1
			default:
				return 0
			}
		})
		for i := 0; i < len(items)-coreHealthMaxEntries; i++ {
			delete(m.routes, items[i].key)
		}
	}
}

func (m *coreHealthManager) load(key string, nowMs int64) (routeHealth, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.cleanupLocked(nowMs)
	entry := m.routes[key]
	if entry.BlockUntilMs == 0 && entry.HalfOpenProbeAtMs > 0 &&
		nowMs-entry.HalfOpenProbeAtMs < coreHalfOpenProbeWait.Milliseconds() {
		return entry.routeHealth, false
	}
	if entry.BlockUntilMs > 0 && entry.BlockUntilMs <= nowMs {
		if nowMs-entry.HalfOpenProbeAtMs < coreHalfOpenProbeWait.Milliseconds() {
			return entry.routeHealth, false
		}
		entry.HalfOpenProbeAtMs = nowMs
		entry.BlockUntilMs = 0
		m.routes[key] = entry
		m.lastDecision = "circuit_half_open:" + key
	}
	return entry.routeHealth, true
}

func (m *coreHealthManager) store(key string, health routeHealth, decision string) {
	nowMs := time.Now().UnixMilli()
	m.lock.Lock()
	entry := m.routes[key]
	entry.routeHealth = health
	if health.BlockUntilMs == 0 {
		entry.HalfOpenProbeAtMs = 0
	}
	m.routes[key] = entry
	m.lastDecision = decision
	m.updatedAtMs = nowMs
	m.cleanupLocked(nowMs)
	m.lock.Unlock()
}

func (m *coreHealthManager) selected(tag, decision string) {
	m.lock.Lock()
	m.selectedOutbound = tag
	m.lastDecision = decision
	m.updatedAtMs = time.Now().UnixMilli()
	m.lock.Unlock()
}

func CoreTelemetry() string {
	nowMs := time.Now().UnixMilli()
	healthManager.syncNetworkScope(nowMs)
	scope := currentNetworkScope()
	adaptiveLock.Lock()
	adaptive := adaptiveByScope[scope]
	adaptiveLock.Unlock()
	healthManager.lock.Lock()
	healthManager.cleanupLocked(nowMs)
	open := 0
	for _, entry := range healthManager.routes {
		if entry.BlockUntilMs > nowMs {
			open++
		}
	}
	snapshot := coreTelemetrySnapshot{
		NetworkScope:     healthManager.networkScope,
		SelectedOutbound: healthManager.selectedOutbound,
		LastDecision:     healthManager.lastDecision,
		RouteCount:       len(healthManager.routes),
		OpenCircuitCount: open,
		Adaptive:         adaptive,
		UpdatedAtMs:      healthManager.updatedAtMs,
	}
	healthManager.lock.Unlock()
	data, _ := json.Marshal(snapshot)
	return string(data)
}

func CoreHealthSnapshot() []coreHealthSnapshot {
	nowMs := time.Now().UnixMilli()
	healthManager.lock.Lock()
	healthManager.cleanupLocked(nowMs)
	items := make([]coreHealthSnapshot, 0, len(healthManager.routes))
	for key, entry := range healthManager.routes {
		items = append(items, coreHealthSnapshot{
			Key:             key,
			LastScore:       entry.LastScore,
			LatencyEWMA:     entry.LatencyEWMA,
			JitterEWMA:      entry.JitterEWMA,
			SuccessStreak:   entry.SuccessStreak,
			FailStreak:      entry.FailStreak,
			BlockUntilMs:    entry.BlockUntilMs,
			HalfOpenProbeAt: entry.HalfOpenProbeAtMs,
			LastUpdatedMs:   entry.LastUpdatedMs,
		})
	}
	healthManager.lock.Unlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].BlockUntilMs != items[j].BlockUntilMs {
			return items[i].BlockUntilMs > items[j].BlockUntilMs
		}
		return items[i].LastUpdatedMs > items[j].LastUpdatedMs
	})
	return items
}

func CoreTelemetryEvents() []coreEvent {
	telemetryLock.Lock()
	events := append([]coreEvent(nil), telemetryEvents...)
	telemetryLock.Unlock()
	return events
}
