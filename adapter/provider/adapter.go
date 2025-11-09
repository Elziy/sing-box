package provider

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type Adapter struct {
	ctx        context.Context
	outbound   adapter.OutboundManager
	router     adapter.Router
	logFactory log.Factory
	logger     log.ContextLogger

	outbounds      []adapter.Outbound
	outboundsByTag map[string]adapter.Outbound
	checking       atomic.Bool
	history        adapter.URLTestHistoryStorage
	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]

	pType string
	tag   string
	path  string
	icon  string

	lastUpdated time.Time
	override    *option.OverrideOptions

	// filter
	includes []*regexp.Regexp
	excludes []*regexp.Regexp
	ports    map[int]bool

	// health check
	link     string
	enabled  bool
	ticker   *time.Ticker
	timeout  time.Duration
	interval time.Duration
}

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, logFactory log.Factory, logger log.ContextLogger,
	providerTag string, providerType string, path string, icon string,
	filter option.FilterOptions, healthCheckOptions option.HealthCheckOptions, override *option.OverrideOptions) Adapter {
	timeout := time.Duration(healthCheckOptions.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(healthCheckOptions.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}

	includes := make([]*regexp.Regexp, 0, len(filter.Includes))
	if len(filter.Includes) > 0 {
		for _, include := range filter.Includes {
			if include == "" {
				continue
			}
			regex, err := regexp.Compile(include)
			if err != nil {
				continue
			}
			includes = append(includes, regex)
		}
	}

	excludes := make([]*regexp.Regexp, 0, len(filter.Excludes))
	if len(filter.Excludes) > 0 {
		for _, exclude := range filter.Excludes {
			if exclude == "" {
				continue
			}
			regex, err := regexp.Compile(exclude)
			if err != nil {
				continue
			}
			excludes = append(excludes, regex)
		}
	}

	var ports map[int]bool
	if len(filter.Ports) > 0 {
		ports, _ = createPortsMap(filter.Ports)
	}

	return Adapter{
		ctx:        ctx,
		outbound:   outbound,
		router:     router,
		logFactory: logFactory,
		logger:     logger,
		pType:      providerType,
		tag:        providerTag,

		path: path,
		icon: icon,

		override: override,

		includes: includes,
		excludes: excludes,
		ports:    ports,

		link:     healthCheckOptions.URL,
		enabled:  healthCheckOptions.Enabled,
		timeout:  timeout,
		interval: interval,
	}
}

func (a *Adapter) PostStart() error {
	a.history = service.FromContext[adapter.URLTestHistoryStorage](a.ctx)
	if a.history == nil {
		if clashServer := service.FromContext[adapter.ClashServer](a.ctx); clashServer != nil {
			a.history = clashServer.HistoryStorage()
		} else {
			a.history = urltest.NewHistoryStorage()
		}
	}
	go a.loopCheck()
	return nil
}

func (a *Adapter) Type() string {
	return a.pType
}

func (a *Adapter) Tag() string {
	return a.tag
}

func (a *Adapter) Path() string {
	return a.path
}

func (a *Adapter) Icon() string {
	return a.icon
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	return a.outbounds
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	if a.outboundsByTag == nil {
		return nil, false
	}
	detour, ok := a.outboundsByTag[tag]
	return detour, ok
}

func (a *Adapter) UpdatedTime() time.Time {
	return a.lastUpdated
}

func (a *Adapter) SetUpdatedTime(updated time.Time) {
	a.lastUpdated = updated
}

func (a *Adapter) UpdateOutbounds(oldOutboundOptions []option.Outbound, newOutboundOptions []option.Outbound) {
	var (
		allOutboundTag          = make(map[string]bool)
		providerOutboundTag     = make(map[string]bool)
		outbounds               = make([]adapter.Outbound, 0, len(newOutboundOptions))
		outboundsByTag          = make(map[string]adapter.Outbound)
		oldOutboundOptionsByTag = make(map[string]option.Outbound)
	)
	for _, oldOutboundOption := range oldOutboundOptions {
		oldOutboundOptionsByTag[oldOutboundOption.Tag] = oldOutboundOption
	}
	for _, outbound := range a.outbounds {
		providerOutboundTag[outbound.Tag()] = true
	}
	for _, o := range a.outbound.Outbounds() {
		if _, exist := providerOutboundTag[o.Tag()]; exist {
			continue
		}
		allOutboundTag[o.Tag()] = true
	}
	for i, newOutboundOption := range newOutboundOptions {
		var tag string
		if newOutboundOption.Tag == "" {
			tag = fmt.Sprint("[", a.tag, "]", F.ToString(i))
		} else {
			tag = newOutboundOption.Tag
		}
		if _, exists := allOutboundTag[tag]; exists {
			j := 1
			for {
				tTag := fmt.Sprint(tag, "[", j, "]")
				if _, exists := allOutboundTag[tTag]; exists {
					j++
					continue
				}
				tag = tTag

				break
			}
		}
		allOutboundTag[tag] = true
		outbound, exist := a.outbound.Outbound(tag)
		if !exist || !reflect.DeepEqual(newOutboundOption, oldOutboundOptionsByTag[newOutboundOption.Tag]) {
			err := a.outbound.Create(
				adapter.WithContext(a.ctx, &adapter.InboundContext{
					Outbound: tag,
				}),
				a.router,
				a.logFactory.NewLogger(F.ToString("outbound/", newOutboundOption.Type, "[", tag, "]")),
				tag,
				newOutboundOption.Type,
				newOutboundOption.Options,
			)
			if err != nil {
				a.logger.Warn(err)
				continue
			}
			outbound, _ = a.outbound.Outbound(tag)
		}
		outbounds = append(outbounds, outbound)
		outboundsByTag[tag] = outbound
	}
	a.removeUselessAndSetOutbounds(outbounds, outboundsByTag)
	if a.enabled && a.history != nil {
		go func() {
			_, _ = a.HealthCheck(a.ctx)
		}()
	}
}

func (a *Adapter) UpdateProviderFromContent(ctx context.Context, content string, oldOutbounds []option.Outbound) ([]option.Outbound, error) {
	defer runtime.GC()
	outbounds, err := parser.Parse(ctx, content, a.override)
	if err != nil {
		return nil, err
	}
	outbounds = a.FilterOutbound(outbounds)
	a.UpdateOutbounds(oldOutbounds, outbounds)
	return outbounds, nil
}

func (a *Adapter) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthCheck(ctx)
}

func (a *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.PushBack(callback)
}

func (a *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	a.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		_ = element.Value(a.tag)
	}
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	outbounds := a.outbounds
	a.outbounds = nil
	var err error
	for _, ob := range outbounds {
		if err2 := a.outbound.Remove(ob.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", ob.Tag(), "]")
			})
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.enabled {
		return
	}
	a.ticker = time.NewTicker(a.interval)
	_, _ = a.healthCheck(a.ctx)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			_, _ = a.healthCheck(a.ctx)
		}
	}
}

func (a *Adapter) healthCheck(ctx context.Context) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if a.checking.Swap(true) {
		return result, nil
	}
	defer a.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	var resultAccess sync.Mutex
	checked := make(map[string]bool)
	for _, detour := range a.outbounds {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(a.ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
			} else {
				a.logger.Debug("outbound ", tag, " available: ", t, "ms")
				a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	_ = b.Wait()
	return result, nil
}

func (a *Adapter) removeUselessAndSetOutbounds(newOutbounds []adapter.Outbound, newOutboundsByTag map[string]adapter.Outbound) {
	for _, outbound := range a.outbounds {
		if _, exist := newOutboundsByTag[outbound.Tag()]; !exist {
			if err := a.outbound.Remove(outbound.Tag()); err != nil {
				a.logger.Error(err, "close outbound [", outbound.Tag(), "]")
			}
		}
	}
	a.outbounds = newOutbounds
	a.outboundsByTag = newOutboundsByTag
}

func (a *Adapter) FilterOutbound(outbounds []option.Outbound) []option.Outbound {
	return common.Filter(outbounds, func(it option.Outbound) bool {
		return testIncludes(it.Tag, a.includes) && testExcludes(it.Tag, a.excludes)
	})
}

func createPortsMap(ports []string) (map[int]bool, error) {
	portReg1 := regexp.MustCompile(`^\d+$`)
	portReg2 := regexp.MustCompile(`^(\d*):(\d*)$`)
	portMap := map[int]bool{}
	for i, portRaw := range ports {
		if matched := portReg1.MatchString(portRaw); matched {
			port, _ := strconv.Atoi(portRaw)
			if port < 0 || port > 65535 {
				return nil, E.New("invalid ports item[", i, "]")
			}
			portMap[port] = true
			continue
		}
		if portRaw == ":" {
			return nil, E.New("invalid ports item[", i, "]")
		}
		if match := portReg2.FindStringSubmatch(portRaw); len(match) == 3 {
			start, _ := strconv.Atoi(match[1])
			end, _ := strconv.Atoi(match[2])
			if start < 0 || start > 65535 {
				return nil, E.New("invalid ports item[", i, "]")
			}
			if end < 0 || end > 65535 {
				return nil, E.New("invalid ports item[", i, "]")
			}
			if end == 0 {
				end = 65535
			}
			if start > end {
				return nil, E.New("invalid ports item[", i, "]")
			}
			for port := start; port <= end; port++ {
				portMap[port] = true
			}
			continue
		}
		return nil, E.New("invalid ports item[", i, "]")
	}
	return portMap, nil
}

func testIncludes(tag string, includes []*regexp.Regexp) bool {
	if len(includes) == 0 {
		return true
	}
	for _, include := range includes {
		if include.MatchString(tag) {
			return true
		}
	}
	return false
}

func testExcludes(tag string, excludes []*regexp.Regexp) bool {
	if len(excludes) == 0 {
		return true
	}
	for _, exclude := range excludes {
		if exclude.MatchString(tag) {
			return false
		}
	}
	return true
}

func testPorts(port int, ports map[int]bool) bool {
	if port == 0 || len(ports) == 0 {
		return true
	}
	_, ok := ports[port]
	return ok
}
