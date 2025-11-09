package parser

import (
	"context"
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json"
	"gopkg.in/yaml.v3"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func Parse(ctx context.Context, content string, overrideDialerOptions *option.OverrideOptions) ([]option.Outbound, error) {
	var outbounds []option.Outbound
	var err error
	switch true {
	case strings.Contains(content, "outbounds"):
		outbounds, err = NewBoxParser(ctx, content)
		if err != nil {
			return nil, err
		}
	case strings.Contains(content, "proxies"):
		outbounds, err = NewClashParser(content)
		if err != nil {
			return nil, err
		}
	default:
		outbounds, err = NewNativeURLParser(content)
		if err != nil {
			return nil, err
		}
	}
	return overrideOutbounds(outbounds, overrideDialerOptions), nil
}

func NewClashParser(content string) ([]option.Outbound, error) {
	var outbounds []option.Outbound
	config := &ClashConfig{
		Proxies: []map[string]any{},
	}
	err := yaml.Unmarshal([]byte(content), config)
	if err != nil {
		return outbounds, err
	}
	for _, proxy := range config.Proxies {
		protocol, exists := proxy["type"]
		if !exists {
			continue
		}
		var (
			outbound option.Outbound
			err      error
		)
		switch protocol {
		case "ss":
			outbound, err = shadowsocks.NewShadowsocksOutboundOption(proxy)
		case "vmess":
			outbound, err = vmess.NewVMessOutboundOption(proxy)
		case "vless":
			outbound, err = vless.NewVLESSOutboundOption(proxy)
		case "trojan":
			outbound, err = trojan.NewTrojanOutboundOption(proxy)
		case "hysteria":
			outbound, err = hysteria.NewHysteriaOutboundOption(proxy)
		case "hysteria2":
			outbound, err = hysteria2.NewHysteria2OutboundOption(proxy)
		case "http":
			outbound, err = http.NewHTTPOutboundOption(proxy)
		case "tuic":
			outbound, err = tuic.NewTUICOutboundOption(proxy)
		case "socks5":
			outbound, err = socks.NewSOCKSOutboundOption(proxy)
		case "wireguard":
			outbound, err = wireguard.NewWireGuardOutboundOption(proxy)
		case "anytls":
			outbound, err = anytls.NewAnyTLSOutboundOption(proxy)
		case "ssh":
			outbound, err = ssh.NewSSHOutboundOption(proxy)
		default:
			continue
		}
		if err == nil {
			outbounds = append(outbounds, outbound)
		}
	}
	return outbounds, nil
}

func NewNativeURLParser(content string) ([]option.Outbound, error) {
	var outbounds []option.Outbound
	for _, raw := range strings.Split(content, "\n") {
		raw = strings.TrimSpace(raw)
		parts := strings.Split(raw, "://")
		if len(parts) < 2 {
			continue
		}
		var (
			outbound option.Outbound
			err      error
		)
		protocol := strings.ToLower(strings.TrimSpace(parts[0]))
		switch protocol {
		case "ss":
			outbound, err = shadowsocks.NewShadowsocksNativeOutboundOption(raw)
		case "vmess":
			outbound, err = vmess.NewVMessNativeOutboundOption(raw)
		case "vless":
			outbound, err = vless.NewVLESSNativeOutboundOption(raw)
		case "trojan":
			outbound, err = trojan.NewTrojanNativeOutboundOption(raw)
		case "hy", "hysteria":
			outbound, err = hysteria.NewHysteriaNativeOutboundOption(raw)
		case "hy2", "hysteria2":
			outbound, err = hysteria2.NewHysteria2NativeOutboundOption(raw)
		case "http":
			outbound, err = http.NewHTTPNativeOutboundOption(raw)
		case "tuic":
			outbound, err = tuic.NewTUICNativeOutboundOption(raw)
		case "socks", "socks5", "socks4", "socks4a":
			outbound, err = socks.NewSOCKSNativeOutboundOption(raw)
		case "wireguard", "wg":
			outbound, err = wireguard.NewWireGuardNativeOutboundOption(raw)
		case "anytls":
			outbound, err = anytls.NewAnyTLSNativeOutboundOption(raw)
		case "ssh":
			outbound, err = ssh.NewSSHNativeOutboundOption(raw)
		default:
			continue
		}
		if err == nil {
			outbounds = append(outbounds, outbound)
		}
	}
	return outbounds, nil
}

func NewBoxParser(ctx context.Context, content string) ([]option.Outbound, error) {
	options, err := json.UnmarshalExtendedContext[option.OutboundProviderOptions](ctx, []byte(content))
	if err != nil {
		return nil, err
	}
	return options.Outbounds, nil
}

func overrideOutbounds(outbounds []option.Outbound, overrideOptions *option.OverrideOptions) []option.Outbound {
	if overrideOptions == nil {
		return outbounds
	}
	var tags []string
	for _, outbound := range outbounds {
		outbound.Tag = overrideOptions.TagPrefix + outbound.Tag + overrideOptions.TagSuffix
		tags = append(tags, outbound.Tag)
	}
	var parsedOutbounds []option.Outbound
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP:
			options := outbound.Options.(*option.HTTPOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeSOCKS:
			options := outbound.Options.(*option.SOCKSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeTUIC:
			options := outbound.Options.(*option.TUICOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeVMess:
			options := outbound.Options.(*option.VMessOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeVLESS:
			options := outbound.Options.(*option.VLESSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeTrojan:
			options := outbound.Options.(*option.TrojanOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeHysteria:
			options := outbound.Options.(*option.HysteriaOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeShadowTLS:
			options := outbound.Options.(*option.ShadowTLSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeHysteria2:
			options := outbound.Options.(*option.Hysteria2OutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeAnyTLS:
			options := outbound.Options.(*option.AnyTLSOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		case C.TypeShadowsocks:
			options := outbound.Options.(*option.ShadowsocksOutboundOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideOptions, tags)
			outbound.Options = options
		}
		parsedOutbounds = append(parsedOutbounds, outbound)
	}
	return parsedOutbounds
}

func overrideDialerOption(options option.DialerOptions, overrideDialerOptions *option.OverrideOptions, tags []string) option.DialerOptions {
	if options.Detour != "" && !common.Any(tags, func(tag string) bool {
		return options.Detour == tag
	}) {
		options.Detour = ""
	}
	var defaultOptions option.OverrideOptions
	if overrideDialerOptions == nil || reflect.DeepEqual(*overrideDialerOptions, defaultOptions) {
		return options
	}
	if overrideDialerOptions.Detour != nil && options.Detour == "" {
		options.Detour = *overrideDialerOptions.Detour
	}
	if overrideDialerOptions.BindInterface != nil {
		options.BindInterface = *overrideDialerOptions.BindInterface
	}
	if overrideDialerOptions.Inet4BindAddress != nil {
		options.Inet4BindAddress = overrideDialerOptions.Inet4BindAddress
	}
	if overrideDialerOptions.Inet6BindAddress != nil {
		options.Inet6BindAddress = overrideDialerOptions.Inet6BindAddress
	}
	if overrideDialerOptions.ProtectPath != nil {
		options.ProtectPath = *overrideDialerOptions.ProtectPath
	}
	if overrideDialerOptions.RoutingMark != nil {
		options.RoutingMark = *overrideDialerOptions.RoutingMark
	}
	if overrideDialerOptions.ReuseAddr != nil {
		options.ReuseAddr = *overrideDialerOptions.ReuseAddr
	}
	if overrideDialerOptions.ConnectTimeout != nil {
		options.ConnectTimeout = *overrideDialerOptions.ConnectTimeout
	}
	if overrideDialerOptions.TCPFastOpen != nil {
		options.TCPFastOpen = *overrideDialerOptions.TCPFastOpen
	}
	if overrideDialerOptions.TCPMultiPath != nil {
		options.TCPMultiPath = *overrideDialerOptions.TCPMultiPath
	}
	if overrideDialerOptions.UDPFragment != nil {
		options.UDPFragment = overrideDialerOptions.UDPFragment
	}
	if overrideDialerOptions.DomainResolver != nil {
		options.DomainResolver = overrideDialerOptions.DomainResolver
	}
	if overrideDialerOptions.NetworkStrategy != nil {
		options.NetworkStrategy = overrideDialerOptions.NetworkStrategy
	}
	if overrideDialerOptions.NetworkType != nil {
		options.NetworkType = *overrideDialerOptions.NetworkType
	}
	if overrideDialerOptions.FallbackNetworkType != nil {
		options.FallbackNetworkType = *overrideDialerOptions.FallbackNetworkType
	}
	if overrideDialerOptions.FallbackDelay != nil {
		options.FallbackDelay = *overrideDialerOptions.FallbackDelay
	}
	if overrideDialerOptions.DomainStrategy != nil {
		options.DomainStrategy = *overrideDialerOptions.DomainStrategy
	}
	return options
}

type ClashConfig struct {
	Proxies []map[string]any `yaml:"proxies"`
}
