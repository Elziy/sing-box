package rule

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

func NewRule(ctx context.Context, logger log.ContextLogger, options option.Rule, checkOutbound bool) (adapter.Rule, error) {
	switch options.Type {
	case "", C.RuleTypeDefault:
		if !options.DefaultOptions.IsValid() {
			return nil, E.New("missing conditions")
		}
		switch options.DefaultOptions.Action {
		case "", C.RuleActionTypeRoute:
			if options.DefaultOptions.RouteOptions.Outbound == "" && checkOutbound {
				return nil, E.New("missing outbound field")
			}
		}
		return NewDefaultRule(ctx, logger, options.DefaultOptions)
	case C.RuleTypeLogical:
		if !options.LogicalOptions.IsValid() {
			return nil, E.New("missing conditions")
		}
		switch options.LogicalOptions.Action {
		case "", C.RuleActionTypeRoute:
			if options.LogicalOptions.RouteOptions.Outbound == "" && checkOutbound {
				return nil, E.New("missing outbound field")
			}
		}
		return NewLogicalRule(ctx, logger, options.LogicalOptions)
	default:
		return nil, E.New("unknown rule type: ", options.Type)
	}
}

var _ adapter.Rule = (*DefaultRule)(nil)

type DefaultRule struct {
	abstractDefaultRule
}

type RuleItem interface {
	Match(metadata *adapter.InboundContext) bool
	String() string
}

func NewDefaultRule(ctx context.Context, logger log.ContextLogger, options option.DefaultRule) (*DefaultRule, error) {
	action, err := NewRuleAction(ctx, logger, options.RuleAction)
	if err != nil {
		return nil, E.Cause(err, "action")
	}
	rule := &DefaultRule{
		abstractDefaultRule{
			invert: options.Invert,
			action: action,
		},
	}
	var ruleCount uint32 = 0
	router := service.FromContext[adapter.Router](ctx)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if len(options.Inbound) > 0 {
		item := NewInboundRule(options.Inbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.inbounds))
	}
	if options.IPVersion > 0 {
		switch options.IPVersion {
		case 4, 6:
			item := NewIPVersionItem(options.IPVersion == 6)
			rule.items = append(rule.items, item)
			rule.allItems = append(rule.allItems, item)
			ruleCount += uint32(1)
		default:
			return nil, E.New("invalid ip version: ", options.IPVersion)
		}
	}
	if len(options.Network) > 0 {
		item := NewNetworkItem(options.Network)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.networks))
	}
	if len(options.AuthUser) > 0 {
		item := NewAuthUserItem(options.AuthUser)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.users))
	}
	if len(options.Protocol) > 0 {
		item := NewProtocolItem(options.Protocol)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.protocols))
	}
	if len(options.Client) > 0 {
		item := NewClientItem(options.Client)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.clients))
	}
	if len(options.Domain) > 0 || len(options.DomainSuffix) > 0 {
		item, err := NewDomainItem(options.Domain, options.DomainSuffix)
		if err != nil {
			return nil, err
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(options.Domain))
		ruleCount += uint32(len(options.DomainSuffix))
	}
	if len(options.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(options.DomainKeyword)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.keywords))
	}
	if len(options.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(options.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(options.DomainRegex))
	}
	if len(options.Geosite) > 0 {
		item := NewGeositeItem(router, logger, options.Geosite)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.SourceGeoIP) > 0 {
		item := NewGeoIPItem(router, logger, true, options.SourceGeoIP)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.GeoIP) > 0 {
		item := NewGeoIPItem(router, logger, false, options.GeoIP)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.SourceIPCIDR) > 0 {
		item, err := NewIPCIDRItem(true, options.SourceIPCIDR)
		if err != nil {
			return nil, E.Cause(err, "source_ip_cidr")
		}
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(options.SourceIPCIDR))
	}
	if options.SourceIPIsPrivate {
		item := NewIPIsPrivateItem(true)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.IPCIDR) > 0 {
		item, err := NewIPCIDRItem(false, options.IPCIDR)
		if err != nil {
			return nil, E.Cause(err, "ipcidr")
		}
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(options.IPCIDR))
	}
	if options.IPIsPrivate {
		item := NewIPIsPrivateItem(false)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.SourcePort) > 0 {
		item := NewPortItem(true, options.SourcePort)
		rule.sourcePortItems = append(rule.sourcePortItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.ports))
	}
	if len(options.SourcePortRange) > 0 {
		item, err := NewPortRangeItem(true, options.SourcePortRange)
		if err != nil {
			return nil, E.Cause(err, "source_port_range")
		}
		rule.sourcePortItems = append(rule.sourcePortItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.portRanges))
	}
	if len(options.Port) > 0 {
		item := NewPortItem(false, options.Port)
		rule.destinationPortItems = append(rule.destinationPortItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.ports))
	}
	if len(options.PortRange) > 0 {
		item, err := NewPortRangeItem(false, options.PortRange)
		if err != nil {
			return nil, E.Cause(err, "port_range")
		}
		rule.destinationPortItems = append(rule.destinationPortItems, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.portRanges))
	}
	if len(options.ProcessName) > 0 {
		item := NewProcessItem(options.ProcessName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.processes))
	}
	if len(options.ProcessPath) > 0 {
		item := NewProcessPathItem(options.ProcessPath)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.processes))
	}
	if len(options.ProcessPathRegex) > 0 {
		item, err := NewProcessPathRegexItem(options.ProcessPathRegex)
		if err != nil {
			return nil, E.Cause(err, "process_path_regex")
		}
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(options.ProcessPathRegex))
	}
	if len(options.PackageName) > 0 {
		item := NewPackageNameItem(options.PackageName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.packageNames))
	}
	if len(options.User) > 0 {
		item := NewUserItem(options.User)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.users))
	}
	if len(options.UserID) > 0 {
		item := NewUserIDItem(options.UserID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.userIds))
	}
	if options.ClashMode != "" {
		item := NewClashModeItem(ctx, options.ClashMode)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.NetworkType) > 0 {
		item := NewNetworkTypeItem(networkManager, common.Map(options.NetworkType, option.InterfaceType.Build))
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.networkType))
	}
	if options.NetworkIsExpensive {
		item := NewNetworkIsExpensiveItem(networkManager)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if options.NetworkIsConstrained {
		item := NewNetworkIsConstrainedItem(networkManager)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(1)
	}
	if len(options.WIFISSID) > 0 {
		item := NewWIFISSIDItem(networkManager, options.WIFISSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.ssidList))
	}
	if len(options.WIFIBSSID) > 0 {
		item := NewWIFIBSSIDItem(networkManager, options.WIFIBSSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		ruleCount += uint32(len(item.bssidList))
	}
	if len(options.RuleSet) > 0 {
		var matchSource bool
		if options.RuleSetIPCIDRMatchSource {
			matchSource = true
		} else
		//nolint:staticcheck
		if options.Deprecated_RulesetIPCIDRMatchSource {
			matchSource = true
			deprecated.Report(ctx, deprecated.OptionBadMatchSource)
		}
		item := NewRuleSetItem(router, options.RuleSet, matchSource, false)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
		rule.ruleSetItem = item
	}
	rule.ruleCount = ruleCount
	return rule, nil
}

var _ adapter.Rule = (*LogicalRule)(nil)

type LogicalRule struct {
	abstractLogicalRule
}

func NewLogicalRule(ctx context.Context, logger log.ContextLogger, options option.LogicalRule) (*LogicalRule, error) {
	action, err := NewRuleAction(ctx, logger, options.RuleAction)
	if err != nil {
		return nil, E.Cause(err, "action")
	}
	rule := &LogicalRule{
		abstractLogicalRule{
			rules:     make([]adapter.HeadlessRule, len(options.Rules)),
			ruleCount: 1,
			invert:    options.Invert,
			action:    action,
		},
	}
	switch options.Mode {
	case C.LogicalTypeAnd:
		rule.mode = C.LogicalTypeAnd
	case C.LogicalTypeOr:
		rule.mode = C.LogicalTypeOr
	default:
		return nil, E.New("unknown logical mode: ", options.Mode)
	}
	for i, subOptions := range options.Rules {
		subRule, err := NewRule(ctx, logger, subOptions, false)
		if err != nil {
			return nil, E.Cause(err, "sub rule[", i, "]")
		}
		rule.rules[i] = subRule
	}
	return rule, nil
}
