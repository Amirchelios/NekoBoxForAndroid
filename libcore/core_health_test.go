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

func TestCurrentAdaptivePolicyDefaults(t *testing.T) {
	adaptiveLock.Lock()
	adaptiveByScope = map[string]adaptiveState{}
	adaptiveLock.Unlock()

	policy := currentAdaptivePolicy()
	if policy.Tuning.MinSwitchIntervalMs < 8_000 {
		t.Fatalf("expected min switch interval >= 8000, got %d", policy.Tuning.MinSwitchIntervalMs)
	}
	if policy.Tuning.BurstLimit < 3 || policy.Tuning.BurstLimit > 8 {
		t.Fatalf("expected burst limit in [3,8], got %d", policy.Tuning.BurstLimit)
	}
	if policy.Tuning.TimeoutBoostMs < 0 || policy.Tuning.TimeoutBoostMs > 1200 {
		t.Fatalf("expected timeout boost in [0,1200], got %d", policy.Tuning.TimeoutBoostMs)
	}
}

func TestCurrentAdaptivePolicyReactive(t *testing.T) {
	adaptiveLock.Lock()
	adaptiveByScope = map[string]adaptiveState{
		currentNetworkScope(): {
			InstabilityEWMA: 1600,
			FailureEWMA:     1800,
			LatencyEWMA:     4200,
		},
	}
	adaptiveLock.Unlock()

	policy := currentAdaptivePolicy()
	if policy.Severity <= 0 {
		t.Fatal("expected severity to increase under unstable conditions")
	}
	if policy.Tuning.MinSwitchIntervalMs < 8_000 {
		t.Fatalf("expected bounded min switch interval, got %d", policy.Tuning.MinSwitchIntervalMs)
	}
	if policy.Tuning.MaxRetry < 2 {
		t.Fatalf("expected max retry not to drop below base, got %d", policy.Tuning.MaxRetry)
	}
}

func TestCoreHealthManagerCircuitProgression(t *testing.T) {
	nowMs := time.Now().UnixMilli()
	key := "network:test|urltest|route"
	manager := coreHealthManager{routes: map[string]coreHealthEntry{
		key: {
			routeHealth: routeHealth{
				FailStreak:    5,
				BlockUntilMs:  nowMs - 1,
				LastUpdatedMs: nowMs,
			},
		},
	}}

	health, allowed := manager.load(key, nowMs)
	if !allowed {
		t.Fatal("expected first expired circuit probe to be allowed")
	}
	if health.BlockUntilMs != 0 {
		t.Fatalf("expected half-open probe to clear block, got %d", health.BlockUntilMs)
	}

	health.FailStreak++
	health.BlockUntilMs = nowMs + 25_000
	manager.store(key, health, "probe_failed:"+key)

	stored, allowed := manager.load(key, nowMs+1)
	if allowed {
		t.Fatal("expected half-open guard to reject immediate re-probe")
	}
	if stored.FailStreak != health.FailStreak {
		t.Fatalf("expected fail streak %d, got %d", health.FailStreak, stored.FailStreak)
	}
}
