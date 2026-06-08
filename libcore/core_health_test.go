package libcore

import (
	"fmt"
	"testing"
	"time"
)

func TestCoreHealthManagerBoundsEntries(t *testing.T) {
	nowMs := time.Now().UnixMilli()
	manager := coreHealthManager{routes: map[string]coreHealthEntry{}}
	for index := 0; index < coreHealthMaxEntries+32; index++ {
		manager.routes[fmt.Sprintf("route-%d", index)] = coreHealthEntry{
			routeHealth: routeHealth{LastUpdatedMs: nowMs + int64(index)},
		}
	}

	manager.cleanupLocked(nowMs + int64(time.Minute/time.Millisecond))

	if len(manager.routes) != coreHealthMaxEntries {
		t.Fatalf("expected %d routes, got %d", coreHealthMaxEntries, len(manager.routes))
	}
}

func TestCoreHealthManagerHalfOpenProbe(t *testing.T) {
	nowMs := time.Now().UnixMilli()
	key := "network:test|route"
	manager := coreHealthManager{routes: map[string]coreHealthEntry{
		key: {
			routeHealth: routeHealth{
				FailStreak:    4,
				BlockUntilMs:  nowMs - 1,
				LastUpdatedMs: nowMs,
			},
		},
	}}

	health, allowed := manager.load(key, nowMs)
	if !allowed || health.BlockUntilMs != 0 {
		t.Fatal("expected the first expired circuit probe to enter half-open state")
	}

	_, allowed = manager.load(key, nowMs+1)
	if allowed {
		t.Fatal("expected concurrent half-open probe to be rejected")
	}
}
