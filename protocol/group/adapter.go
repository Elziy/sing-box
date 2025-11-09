package group

import (
	"context"
	"regexp"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

type Adapter struct {
	outbound.Adapter
	icon                         string
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	provider                     adapter.ProviderManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	outbounds                    map[string]adapter.Outbound
	outboundsCache               map[string][]adapter.Outbound
	providers                    map[string]adapter.Provider
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	updating                     atomic.Bool

	providerTags    []string
	includes        []*regexp.Regexp
	excludes        []*regexp.Regexp
	useAllProviders bool
}

func NewAdapter(
	groupType string,
	tag string,
	icon string,
	networks []string,
	outbounds []string,
	ctx context.Context,
	logger log.ContextLogger,
	providerTags []string,
	includes []string,
	excludes []string,
	useAllProviders bool,
	interruptExternalConnections bool,
) (*Adapter, error) {
	includesRegex := make([]*regexp.Regexp, 0, len(includes))
	for _, include := range includes {
		if include == "" {
			continue
		}
		regex, err := regexp.Compile(include)
		if err != nil {
			continue
		}
		includesRegex = append(includesRegex, regex)
	}

	excludesRegex := make([]*regexp.Regexp, 0, len(excludes))
	for _, exclude := range excludes {
		if exclude == "" {
			continue
		}
		regex, err := regexp.Compile(exclude)
		if err != nil {
			continue
		}
		excludesRegex = append(excludesRegex, regex)
	}

	return &Adapter{
		Adapter:                      outbound.NewAdapter(groupType, tag, networks, outbounds),
		icon:                         icon,
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		provider:                     service.FromContext[adapter.ProviderManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         outbounds,
		outbounds:                    make(map[string]adapter.Outbound),
		outboundsCache:               make(map[string][]adapter.Outbound),
		providers:                    make(map[string]adapter.Provider),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		providerTags:                 providerTags,
		includes:                     includesRegex,
		excludes:                     excludesRegex,
		useAllProviders:              useAllProviders,
	}, nil
}

func (a *Adapter) Icon() string {
	return a.icon
}

func (a *Adapter) InitializeProviders(callback func(string) error) error {
	providers := make(map[string]adapter.Provider)

	if a.useAllProviders {
		var providerTags []string
		for _, provider := range a.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			providers[provider.Tag()] = provider
			provider.RegisterCallback(callback)
		}
		a.providerTags = providerTags
	} else {
		for i, tag := range a.providerTags {
			provider, loaded := a.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			providers[tag] = provider
			provider.RegisterCallback(callback)
		}
	}

	a.providers = providers

	if len(a.tags)+len(a.providerTags) == 0 {
		return E.New("missing outbound and provider outboundTags")
	}

	return nil
}

func (a *Adapter) FilterOutbounds(updatedTag string) ([]string, map[string]adapter.Outbound, []adapter.Outbound, error) {
	var (
		tags          = a.Dependencies()
		outboundByTag = make(map[string]adapter.Outbound)
		outbounds     []adapter.Outbound
	)

	for i, tag := range tags {
		detour, loaded := a.outbound.Outbound(tag)
		if !loaded {
			return nil, nil, nil, E.New("outbound ", i, " not found: ", tag)
		}
		outboundByTag[tag] = detour
		outbounds = append(outbounds, detour)
	}

	for _, providerTag := range a.providerTags {
		if providerTag != updatedTag && a.outboundsCache[providerTag] != nil {
			for _, detour := range a.outboundsCache[providerTag] {
				tags = append(tags, detour.Tag())
				outboundByTag[detour.Tag()] = detour
			}
			outbounds = append(outbounds, a.outboundsCache[providerTag]...)
			continue
		}

		provider := a.providers[providerTag]
		var cache []adapter.Outbound

		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()

			excluded := false
			if len(a.excludes) != 0 {
				for _, exclude := range a.excludes {
					if exclude.MatchString(tag) {
						excluded = true
						break
					}
				}
			}
			if excluded {
				continue
			}

			if len(a.includes) != 0 && common.All(a.includes, func(it *regexp.Regexp) bool {
				return !it.MatchString(tag)
			}) {
				continue
			}

			tags = append(tags, tag)
			cache = append(cache, detour)
			outboundByTag[tag] = detour
		}

		outbounds = append(outbounds, cache...)
		a.outboundsCache[providerTag] = cache
	}

	if len(tags) == 0 {
		detour, _ := a.outbound.Outbound(C.OUTBOUNDLESS)
		tags = append(tags, detour.Tag())
		outboundByTag[detour.Tag()] = detour
		outbounds = append(outbounds, detour)
	}

	return tags, outboundByTag, outbounds, nil
}

func (a *Adapter) InterruptConnections() {
	a.interruptGroup.Interrupt(a.interruptExternalConnections)
}

func (a *Adapter) IsUpdating() bool {
	return a.updating.Load()
}

func (a *Adapter) SetUpdating(updating bool) bool {
	return a.updating.Swap(updating)
}

func (a *Adapter) GetProviders() map[string]adapter.Provider {
	return a.providers
}

func (a *Adapter) GetOutbounds() map[string]adapter.Outbound {
	return a.outbounds
}

func (a *Adapter) SetOutbounds(outbounds map[string]adapter.Outbound) {
	a.outbounds = outbounds
}

func (a *Adapter) GetTags() []string {
	return a.tags
}

func (a *Adapter) SetTags(tags []string) {
	a.tags = tags
}

func (a *Adapter) GetLogger() log.ContextLogger {
	return a.logger
}

func (a *Adapter) GetContext() context.Context {
	return a.ctx
}

func (a *Adapter) GetInterruptGroup() *interrupt.Group {
	return a.interruptGroup
}

func (a *Adapter) GetConnectionManager() adapter.ConnectionManager {
	return a.connection
}

func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		return group.Now()
	}
	return detour.Tag()
}
