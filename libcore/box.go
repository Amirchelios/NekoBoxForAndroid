package libcore

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"libcore/device"
	"log"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matsuridayo/libneko/protect_server"
	"github.com/matsuridayo/libneko/speedtest"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/boxapi"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/protocol/group"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/conntrack"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func init() {
	dialer.DoNotSelectInterface = true
}

var mainInstance *BoxInstance

func VersionBox() string {
	version := []string{
		"sing-box: " + constant.Version,
		runtime.Version() + "@" + runtime.GOOS + "/" + runtime.GOARCH,
	}

	var tags string
	debugInfo, loaded := debug.ReadBuildInfo()
	if loaded {
		for _, setting := range debugInfo.Settings {
			switch setting.Key {
			case "-tags":
				tags = setting.Value
			}
		}
	}

	if tags != "" {
		version = append(version, tags)
	}

	return strings.Join(version, "\n")
}

func ResetAllConnections(system bool) {
	if system {
		conntrack.Close()
		log.Println("Reset system connections done")
	} else {
		log.Println("TODO: Reset user connections")
	}
}

type BoxInstance struct {
	access sync.Mutex

	*box.Box
	cancel context.CancelFunc
	state  int

	v2api        *boxapi.SbV2rayServer
	selector     *group.Selector
	pauseManager pause.Manager

	selectLock          sync.Mutex
	selectedOutboundTag string
	lastSelectAtMs      int64
	rapidSwitchRejects  int
	switchTimestamps    []int64
	switchHoldUntilMs   int64

	routeKey string
}

const (
	coreSelectorMinSwitchIntervalMs = int64(15_000)
	coreSelectorForceSwitchAfter    = 3
	coreSelectorBurstWindowMs       = int64(120_000)
	coreSelectorBurstLimit          = 5
	coreSelectorBurstHoldMs         = int64(45_000)
	coreUrltestMaxRetry             = 2
	coreUrltestRetryPenalty         = int32(80)
	coreUrltestSingleShotPenalty    = int32(180)
	coreUrltestFallbackPenalty      = int32(260)
	coreUrltestBlockedBasePenalty   = int32(6_000)
	coreUrltestHealthFailPenalty    = int32(120)
	coreUrltestHealthJitterCap      = int32(220)
	coreUrltestHealthStableBonus    = int32(90)
	coreUrltestCircuitFailTrigger   = 4
	coreUrltestCircuitBlockBaseMs   = int64(25_000)
	coreUrltestCircuitBlockMaxMs    = int64(180_000)
)

type routeHealth struct {
	LastScore     int32
	LatencyEWMA   int32
	JitterEWMA    int32
	SuccessStreak int
	FailStreak    int
	BlockUntilMs  int64
	LastUpdatedMs int64
}

type adaptiveState struct {
	InstabilityEWMA int32
	FailureEWMA     int32
	LatencyEWMA     int32
	UpdatedAtMs     int64
}

type adaptiveTuning struct {
	MinSwitchIntervalMs int64
	BurstLimit          int
	BurstHoldMs         int64
	MaxRetry            int
	TimeoutBoostMs      int32
	FailPenalty         int32
	StableBonus         int32
}

var (
	routeHealthLock sync.Mutex
	routeHealthMap  = map[string]routeHealth{}
	adaptiveLock    sync.Mutex
	adaptiveCore    adaptiveState
	telemetryLock   sync.Mutex
	telemetryLastMs = map[string]int64{}
)

func routeKeyFromConfig(config string) string {
	if config == "" {
		return "cfg:empty"
	}
	sum := crc32.ChecksumIEEE([]byte(config))
	return fmt.Sprintf("cfg:%08x:%d", sum, len(config))
}

func routeKeyForInstance(i *BoxInstance, link string) string {
	if i != nil && i.routeKey != "" {
		return i.routeKey
	}
	if mainInstance != nil && mainInstance.routeKey != "" {
		return "main:" + mainInstance.routeKey + ":" + link
	}
	return "direct:" + link
}

func loadRouteHealth(key string) routeHealth {
	routeHealthLock.Lock()
	defer routeHealthLock.Unlock()
	return routeHealthMap[key]
}

func storeRouteHealth(key string, h routeHealth) {
	routeHealthLock.Lock()
	routeHealthMap[key] = h
	routeHealthLock.Unlock()
}

func clampInt32(v, min, max int32) int32 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func currentAdaptiveTuning() adaptiveTuning {
	adaptiveLock.Lock()
	state := adaptiveCore
	adaptiveLock.Unlock()

	severity := int32(0)
	severity += clampInt32(state.InstabilityEWMA/80, 0, 8)
	severity += clampInt32(state.FailureEWMA/160, 0, 8)
	severity += clampInt32((state.LatencyEWMA-800)/450, 0, 6)
	if severity > 14 {
		severity = 14
	}

	t := adaptiveTuning{
		MinSwitchIntervalMs: coreSelectorMinSwitchIntervalMs + int64(severity)*2_200,
		BurstLimit:          coreSelectorBurstLimit - int(severity/5),
		BurstHoldMs:         coreSelectorBurstHoldMs + int64(severity)*4_000,
		MaxRetry:            coreUrltestMaxRetry + int(severity/4),
		TimeoutBoostMs:      severity * 120,
		FailPenalty:         coreUrltestHealthFailPenalty + severity*12,
		StableBonus:         coreUrltestHealthStableBonus + severity*8,
	}
	if t.BurstLimit < 3 {
		t.BurstLimit = 3
	}
	if t.MaxRetry > 5 {
		t.MaxRetry = 5
	}
	if t.MinSwitchIntervalMs > 45_000 {
		t.MinSwitchIntervalMs = 45_000
	}
	if t.BurstHoldMs > 90_000 {
		t.BurstHoldMs = 90_000
	}
	if t.TimeoutBoostMs > 1_200 {
		t.TimeoutBoostMs = 1_200
	}
	return t
}

func adaptiveUpdateOnSwitchReject() {
	nowMs := time.Now().UnixMilli()
	adaptiveLock.Lock()
	adaptiveCore.InstabilityEWMA = clampInt32((adaptiveCore.InstabilityEWMA*8+220)/9, 0, 2500)
	adaptiveCore.UpdatedAtMs = nowMs
	adaptiveLock.Unlock()
}

func adaptiveUpdateOnUrlSuccess(score int32, jitter int32) {
	nowMs := time.Now().UnixMilli()
	adaptiveLock.Lock()
	adaptiveCore.LatencyEWMA = clampInt32((adaptiveCore.LatencyEWMA*7+score*3)/10, 0, 20000)
	adaptiveCore.InstabilityEWMA = clampInt32((adaptiveCore.InstabilityEWMA*8+jitter*2)/10, 0, 2500)
	adaptiveCore.FailureEWMA = clampInt32((adaptiveCore.FailureEWMA*7)/10, 0, 2500)
	adaptiveCore.UpdatedAtMs = nowMs
	adaptiveLock.Unlock()
}

func adaptiveUpdateOnUrlFail(failStreak int) {
	nowMs := time.Now().UnixMilli()
	bump := int32(260 + failStreak*80)
	adaptiveLock.Lock()
	adaptiveCore.FailureEWMA = clampInt32((adaptiveCore.FailureEWMA*8+bump*2)/10, 0, 2500)
	adaptiveCore.InstabilityEWMA = clampInt32((adaptiveCore.InstabilityEWMA*8+170)/9, 0, 2500)
	adaptiveCore.UpdatedAtMs = nowMs
	adaptiveLock.Unlock()
}

func telemetryLog(kind string, minIntervalMs int64, format string, args ...any) {
	nowMs := time.Now().UnixMilli()
	telemetryLock.Lock()
	last := telemetryLastMs[kind]
	if nowMs-last < minIntervalMs {
		telemetryLock.Unlock()
		return
	}
	telemetryLastMs[kind] = nowMs
	telemetryLock.Unlock()
	log.Printf("[core/%s] %s", kind, fmt.Sprintf(format, args...))
}

func NewSingBoxInstance(config string, localTransport LocalDNSTransport) (b *BoxInstance, err error) {
	defer device.DeferPanicToError("NewSingBoxInstance", func(err_ error) { err = err_ })

	// create box context
	ctx, cancel := context.WithCancel(context.Background())
	ctx = box.Context(ctx,
		nekoboxAndroidInboundRegistry(), nekoboxAndroidOutboundRegistry(), nekoboxAndroidEndpointRegistry(),
		nekoboxAndroidDNSTransportRegistry(localTransport), nekoboxAndroidServiceRegistry(),
	)
	ctx = service.ContextWithDefaultRegistry(ctx)
	service.MustRegister[platform.Interface](ctx, boxPlatformInterfaceInstance)

	// parse options
	var options option.Options
	err = options.UnmarshalJSONContext(ctx, []byte(config))
	if err != nil {
		return nil, fmt.Errorf("decode config: %v", err)
	}

	// create box
	instance, err := box.New(box.Options{
		Options:           options,
		Context:           ctx,
		PlatformLogWriter: boxPlatformLogWriter,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create service: %v", err)
	}

	b = &BoxInstance{
		Box:          instance,
		cancel:       cancel,
		pauseManager: service.FromContext[pause.Manager](ctx),
		routeKey:     routeKeyFromConfig(config),
	}

	// selector
	if proxy, ok := b.Outbound().Outbound("proxy"); ok {
		if selector, ok := proxy.(*group.Selector); ok {
			b.selector = selector
		}
	}

	return b, nil
}

func (b *BoxInstance) Start() (err error) {
	b.access.Lock()
	defer b.access.Unlock()

	defer device.DeferPanicToError("box.Start", func(err_ error) { err = err_ })

	if b.state == 0 {
		b.state = 1
		return b.Box.Start()
	}
	return errors.New("already started")
}

func (b *BoxInstance) Close() (err error) {
	b.access.Lock()
	defer b.access.Unlock()

	defer device.DeferPanicToError("box.Close", func(err_ error) { err = err_ })

	// no double close
	if b.state == 2 {
		return nil
	}
	b.state = 2

	// clear main instance
	if mainInstance == b {
		mainInstance = nil
		goServeProtect(false)
	}

	// close box
	if b.cancel != nil {
		b.cancel()
	}
	if b.Box != nil {
		b.Box.Close()
	}

	return nil
}

func (b *BoxInstance) Sleep() {
	if b.pauseManager != nil {
		b.pauseManager.DevicePause()
	}
	// _ = b.Box.Router().ResetNetwork()
}

func (b *BoxInstance) Wake() {
	if b.pauseManager != nil {
		b.pauseManager.DeviceWake()
	}
}

func (b *BoxInstance) SetAsMain() {
	mainInstance = b
	goServeProtect(true)
}

func (b *BoxInstance) SetV2rayStats(outbounds string) {
	b.access.Lock()
	defer b.access.Unlock()
	if b.v2api != nil {
		log.Println("duplicate call of SetV2rayStats")
		return
	}
	b.v2api = boxapi.NewSbV2rayServer(option.V2RayStatsServiceOptions{
		Enabled:   true,
		Outbounds: strings.Split(outbounds, "\n"),
	})
	b.Box.Router().AppendTracker(b.v2api.StatsService())
}

func (b *BoxInstance) QueryStats(tag, direct string) int64 {
	if b.v2api == nil {
		return 0
	}
	return b.v2api.QueryStats(fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, direct))
}

func (b *BoxInstance) SelectOutbound(tag string) bool {
	if b.selector != nil {
		nowMs := time.Now().UnixMilli()
		tuning := currentAdaptiveTuning()
		b.selectLock.Lock()
		defer b.selectLock.Unlock()

		if tag == "" {
			telemetryLog("select_skip", 3000, "skip empty tag")
			return false
		}
		if b.selectedOutboundTag == tag {
			b.lastSelectAtMs = nowMs
			b.rapidSwitchRejects = 0
			return true
		}
		if b.switchHoldUntilMs > nowMs {
			b.rapidSwitchRejects++
			if b.rapidSwitchRejects < coreSelectorForceSwitchAfter {
				adaptiveUpdateOnSwitchReject()
				remain := b.switchHoldUntilMs - nowMs
				telemetryLog(
					"select_hold",
					2000,
					"reject switch from=%s to=%s hold_remain_ms=%d rejects=%d",
					b.selectedOutboundTag,
					tag,
					remain,
					b.rapidSwitchRejects,
				)
				return false
			}
		}
		if b.selectedOutboundTag != "" && nowMs-b.lastSelectAtMs < tuning.MinSwitchIntervalMs {
			b.rapidSwitchRejects++
			if b.rapidSwitchRejects < coreSelectorForceSwitchAfter {
				adaptiveUpdateOnSwitchReject()
				telemetryLog(
					"select_interval",
					2000,
					"reject fast switch from=%s to=%s elapsed_ms=%d min_ms=%d rejects=%d",
					b.selectedOutboundTag,
					tag,
					nowMs-b.lastSelectAtMs,
					tuning.MinSwitchIntervalMs,
					b.rapidSwitchRejects,
				)
				return false
			}
		}
		ok := b.selector.SelectOutbound(tag)
		if ok {
			b.selectedOutboundTag = tag
			b.lastSelectAtMs = nowMs
			b.rapidSwitchRejects = 0
			cutoffMs := nowMs - coreSelectorBurstWindowMs
			kept := b.switchTimestamps[:0]
			for _, ts := range b.switchTimestamps {
				if ts >= cutoffMs {
					kept = append(kept, ts)
				}
			}
			b.switchTimestamps = append(kept, nowMs)
			if len(b.switchTimestamps) >= tuning.BurstLimit {
				b.switchHoldUntilMs = nowMs + tuning.BurstHoldMs
				adaptiveUpdateOnSwitchReject()
				telemetryLog(
					"select_burst",
					1500,
					"burst detected count=%d limit=%d hold_ms=%d",
					len(b.switchTimestamps),
					tuning.BurstLimit,
					tuning.BurstHoldMs,
				)
			}
			telemetryLog(
				"select_ok",
				1200,
				"switch ok to=%s min_interval_ms=%d burst_limit=%d",
				tag,
				tuning.MinSwitchIntervalMs,
				tuning.BurstLimit,
			)
		} else {
			telemetryLog(
				"select_fail",
				1200,
				"switch failed from=%s to=%s",
				b.selectedOutboundTag,
				tag,
			)
		}
		return ok
	}
	return false
}

func UrlTest(i *BoxInstance, link string, timeout int32) (latency int32, err error) {
	defer device.DeferPanicToError("box.UrlTest", func(err_ error) { err = err_ })
	nowMs := time.Now().UnixMilli()
	tuning := currentAdaptiveTuning()
	healthKey := routeKeyForInstance(i, link)
	health := loadRouteHealth(healthKey)
	if health.BlockUntilMs > nowMs {
		waitPenalty := int32((health.BlockUntilMs - nowMs) / 1000 * 40)
		if waitPenalty < 0 {
			waitPenalty = 0
		}
		telemetryLog(
			"urltest_block",
			1500,
			"blocked key=%s remain_ms=%d fail_streak=%d",
			healthKey,
			health.BlockUntilMs-nowMs,
			health.FailStreak,
		)
		return coreUrltestBlockedBasePenalty + waitPenalty + int32(health.FailStreak*90), nil
	}
	rawTest := func(timeoutMs int32) (int32, error) {
		var connectionTracker adapter.ConnectionTracker
		// test i
		if i != nil {
			if i.v2api != nil {
				connectionTracker = i.v2api.StatsService()
			}
			return speedtest.UrlTest(
				boxapi.CreateProxyHttpClient(i.Box, connectionTracker),
				link,
				timeoutMs,
				speedtest.UrlTestStandard_RTT,
			)
		}
		// test direct
		if mainInstance == nil {
			return speedtest.UrlTest(
				boxapi.CreateProxyHttpClient(nil, nil),
				link,
				timeoutMs,
				speedtest.UrlTestStandard_RTT,
			)
		}
		// test mainInstance
		if mainInstance.v2api != nil {
			connectionTracker = mainInstance.v2api.StatsService()
		}
		return speedtest.UrlTest(
			boxapi.CreateProxyHttpClient(mainInstance.Box, connectionTracker),
			link,
			timeoutMs,
			speedtest.UrlTestStandard_RTT,
		)
	}

	if timeout <= 0 {
		timeout = 1500
	}
	if timeout < 900 {
		timeout = 900
	}
	if timeout > 15000 {
		timeout = 15000
	}
	timeout += tuning.TimeoutBoostMs
	if health.LatencyEWMA > 1800 {
		timeout += 600
	}
	if health.LatencyEWMA > 2800 {
		timeout += 900
	}
	if timeout > 15000 {
		timeout = 15000
	}

	dynamicRetry := tuning.MaxRetry
	if dynamicRetry < coreUrltestMaxRetry {
		dynamicRetry = coreUrltestMaxRetry
	}
	if health.FailStreak >= 2 {
		dynamicRetry++
	}
	if health.FailStreak >= 4 {
		dynamicRetry++
	}
	if dynamicRetry > 6 {
		dynamicRetry = 6
	}
	telemetryLog(
		"urltest_tuning",
		3000,
		"key=%s timeout_ms=%d retry=%d fail_streak=%d latency_ewma=%d",
		healthKey,
		timeout,
		dynamicRetry,
		health.FailStreak,
		health.LatencyEWMA,
	)

	results := make([]int32, 0, dynamicRetry)
	var lastErr error
	for attempt := 0; attempt < dynamicRetry; attempt++ {
		t := timeout - int32(attempt*400)
		if t < 900 {
			t = 900
		}
		v, e := rawTest(t)
		if e == nil && v > 0 {
			results = append(results, v)
			continue
		}
		lastErr = e
	}
	if len(results) == 0 {
		backupLinks := []string{
			"https://cp.cloudflare.com/generate_204",
			"https://www.gstatic.com/generate_204",
		}
		fallbackTimeout := timeout
		if fallbackTimeout > 2000 {
			fallbackTimeout = 2000
		}
		for _, fallback := range backupLinks {
			origLink := link
			link = fallback
			v, e := rawTest(fallbackTimeout)
			link = origLink
			if e == nil && v > 0 {
				results = append(results, v)
			} else {
				lastErr = e
			}
		}
		if len(results) == 0 {
			health.FailStreak++
			health.SuccessStreak = 0
			health.LastUpdatedMs = nowMs
			adaptiveUpdateOnUrlFail(health.FailStreak)
			if health.FailStreak >= coreUrltestCircuitFailTrigger {
				blockMs := coreUrltestCircuitBlockBaseMs * int64(health.FailStreak-coreUrltestCircuitFailTrigger+1)
				if blockMs > coreUrltestCircuitBlockMaxMs {
					blockMs = coreUrltestCircuitBlockMaxMs
				}
				health.BlockUntilMs = nowMs + blockMs
				telemetryLog(
					"urltest_circuit",
					1200,
					"open circuit key=%s fail_streak=%d block_ms=%d",
					healthKey,
					health.FailStreak,
					blockMs,
				)
			}
			storeRouteHealth(healthKey, health)
			telemetryLog(
				"urltest_fail",
				1200,
				"hard fail key=%s fail_streak=%d",
				healthKey,
				health.FailStreak,
			)
			if lastErr != nil {
				return 0, lastErr
			}
			return 0, errors.New("url test failed")
		}
		sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
		best := results[0]
		failPenalty := int32(dynamicRetry-len(results)) * 120
		score := best + coreUrltestFallbackPenalty + failPenalty
		jitter := int32(0)
		if len(results) > 1 {
			jitter = results[len(results)-1] - results[0]
		}
		if health.LatencyEWMA == 0 {
			health.LatencyEWMA = score
		} else {
			health.LatencyEWMA = (health.LatencyEWMA*7 + score*3) / 10
		}
		health.JitterEWMA = (health.JitterEWMA*7 + jitter*3) / 10
		health.LastScore = score
		health.SuccessStreak++
		health.FailStreak = 0
		health.BlockUntilMs = 0
		health.LastUpdatedMs = nowMs
		storeRouteHealth(healthKey, health)
		adaptiveUpdateOnUrlSuccess(score, jitter)
		telemetryLog(
			"urltest_fallback_ok",
			1000,
			"key=%s score=%d jitter=%d",
			healthKey,
			score,
			jitter,
		)
		return score, nil
	}

	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	best := results[0]
	if len(results) == 1 {
		score := best + coreUrltestSingleShotPenalty
		if health.FailStreak > 0 {
			score += int32(health.FailStreak) * tuning.FailPenalty
		}
		if health.LatencyEWMA == 0 {
			health.LatencyEWMA = score
		} else {
			health.LatencyEWMA = (health.LatencyEWMA*7 + score*3) / 10
		}
		health.JitterEWMA = (health.JitterEWMA * 8) / 10
		health.LastScore = score
		health.SuccessStreak++
		health.FailStreak = 0
		health.BlockUntilMs = 0
		health.LastUpdatedMs = nowMs
		storeRouteHealth(healthKey, health)
		adaptiveUpdateOnUrlSuccess(score, 0)
		telemetryLog(
			"urltest_single",
			1000,
			"key=%s score=%d",
			healthKey,
			score,
		)
		return score, nil
	}
	worst := results[len(results)-1]
	jitterPenalty := (worst - best) / 2
	retryPenalty := int32(dynamicRetry-len(results)) * coreUrltestRetryPenalty
	healthPenalty := int32(0)
	if health.FailStreak > 0 {
		healthPenalty += int32(health.FailStreak) * tuning.FailPenalty
	}
	historyJitterPenalty := clampInt32(health.JitterEWMA/2, 0, coreUrltestHealthJitterCap)
	healthPenalty += historyJitterPenalty
	stableBonus := int32(0)
	if health.SuccessStreak >= 3 && health.FailStreak == 0 {
		stableBonus = tuning.StableBonus
	}
	score := best + jitterPenalty + retryPenalty + healthPenalty - stableBonus
	if score < 1 {
		score = 1
	}
	if health.LatencyEWMA == 0 {
		health.LatencyEWMA = score
	} else {
		health.LatencyEWMA = (health.LatencyEWMA*7 + score*3) / 10
	}
	jitter := worst - best
	if health.JitterEWMA == 0 {
		health.JitterEWMA = jitter
	} else {
		health.JitterEWMA = (health.JitterEWMA*7 + jitter*3) / 10
	}
	health.LastScore = score
	health.SuccessStreak++
	health.FailStreak = 0
	health.BlockUntilMs = 0
	health.LastUpdatedMs = nowMs
	storeRouteHealth(healthKey, health)
	adaptiveUpdateOnUrlSuccess(score, jitter)
	telemetryLog(
		"urltest_ok",
		900,
		"key=%s score=%d best=%d worst=%d jitter=%d retries=%d",
		healthKey,
		score,
		best,
		worst,
		jitter,
		dynamicRetry,
	)
	return score, nil
}

var protectCloser io.Closer

func goServeProtect(start bool) {
	if protectCloser != nil {
		protectCloser.Close()
		protectCloser = nil
	}
	if start {
		protectCloser = protect_server.ServeProtect("protect_path", false, 0, func(fd int) {
			intfBox.AutoDetectInterfaceControl(int32(fd))
		})
	}
}
