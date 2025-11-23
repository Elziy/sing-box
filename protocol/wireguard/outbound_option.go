package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewWireGuardNativeOutboundOption(content string) (option.Outbound, error) {
	wgURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseWireGuardURL(wgURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewWireGuardOutboundOption(config)
}

func NewWireGuardOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeWireGuard,
	}
	options := &option.LegacyWireGuardOutboundOptions{}
	if name, exists := config["name"].(string); exists {
		outbound.Tag = name
	}
	if server, exists := config["server"].(string); exists {
		options.Server = server
	}
	if port, exists := config["port"]; exists {
		intNum, err := strconv.Atoi(fmt.Sprint(port))
		if err != nil {
			return outbound, E.New("invalid port: ", port)
		}
		options.ServerPort = uint16(intNum)
	}
	// System Interface
	if systemInterface, exists := config["system_interface"].(bool); exists {
		options.SystemInterface = systemInterface
	} else if systemInterface, exists := config["system-interface"].(bool); exists {
		options.SystemInterface = systemInterface
	}
	// GSO (Generic Segmentation Offload)
	if gso, exists := config["gso"].(bool); exists {
		options.GSO = gso
	}
	// Interface Name
	if interfaceName, exists := config["interface_name"].(string); exists {
		options.InterfaceName = interfaceName
	} else if interfaceName, exists := config["interface-name"].(string); exists {
		options.InterfaceName = interfaceName
	}
	// Local Address (client IP in the WireGuard network)
	options.LocalAddress = []netip.Prefix{}
	if localAddr, exists := config["local_address"]; exists {
		switch v := localAddr.(type) {
		case string:
			if prefix, err := netip.ParsePrefix(v); err == nil {
				options.LocalAddress = append(options.LocalAddress, prefix)
			} else if addr, err := netip.ParseAddr(v); err == nil {
				// Convert single IP to prefix
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				prefix := netip.PrefixFrom(addr, bits)
				options.LocalAddress = append(options.LocalAddress, prefix)
			}
		case []string:
			for _, addr := range v {
				if prefix, err := netip.ParsePrefix(addr); err == nil {
					options.LocalAddress = append(options.LocalAddress, prefix)
				} else if ip, err := netip.ParseAddr(addr); err == nil {
					bits := 32
					if ip.Is6() {
						bits = 128
					}
					prefix := netip.PrefixFrom(ip, bits)
					options.LocalAddress = append(options.LocalAddress, prefix)
				}
			}
		case []any:
			for _, item := range v {
				if addr, ok := item.(string); ok {
					if prefix, err := netip.ParsePrefix(addr); err == nil {
						options.LocalAddress = append(options.LocalAddress, prefix)
					} else if ip, err := netip.ParseAddr(addr); err == nil {
						bits := 32
						if ip.Is6() {
							bits = 128
						}
						prefix := netip.PrefixFrom(ip, bits)
						options.LocalAddress = append(options.LocalAddress, prefix)
					}
				}
			}
		}
	}
	if ip, exists := config["ip"].(string); exists {
		prefix, _ := netip.ParsePrefix(ip)
		options.LocalAddress = append(options.LocalAddress, prefix)
	}
	if ip, exists := config["ipv6"].(string); exists {
		prefix, _ := netip.ParsePrefix(ip)
		options.LocalAddress = append(options.LocalAddress, prefix)
	}
	// Private Key (required)
	if privateKey, exists := config["private_key"].(string); exists {
		options.PrivateKey = privateKey
	} else if privateKey, exists := config["private-key"].(string); exists {
		options.PrivateKey = privateKey
	}
	// Peer Public Key (required for single peer mode)
	if peerPublicKey, exists := config["peer_public_key"].(string); exists {
		options.PeerPublicKey = peerPublicKey
	} else if peerPublicKey, exists := config["peer-public-key"].(string); exists {
		options.PeerPublicKey = peerPublicKey
	} else if peerPublicKey, exists := config["public-key"].(string); exists {
		options.PeerPublicKey = peerPublicKey
	}
	// Pre-shared Key
	if preSharedKey, exists := config["pre_shared_key"].(string); exists {
		options.PreSharedKey = preSharedKey
	} else if preSharedKey, exists := config["pre-shared-key"].(string); exists {
		options.PreSharedKey = preSharedKey
	} else if preSharedKey, exists := config["psk"].(string); exists {
		options.PreSharedKey = preSharedKey
	}
	// Reserved bytes
	if reserved, exists := config["reserved"]; exists {
		switch v := reserved.(type) {
		case string:
			if bytes, err := parseReservedBytes(v); err == nil {
				options.Reserved = bytes
			}
		case []uint8:
			options.Reserved = v
		case []int:
			var bytes []uint8
			for _, b := range v {
				bytes = append(bytes, uint8(b))
			}
			options.Reserved = bytes
		case []any:
			var bytes []uint8
			for _, item := range v {
				switch val := item.(type) {
				case float64:
					bytes = append(bytes, uint8(val))
				case int:
					bytes = append(bytes, uint8(val))
				}
			}
			if len(bytes) > 0 {
				options.Reserved = bytes
			}
		}
	}
	// Workers
	if workers, exists := config["workers"]; exists {
		if w, err := strconv.Atoi(fmt.Sprint(workers)); err == nil {
			options.Workers = w
		}
	}
	// MTU
	if mtu, exists := config["mtu"]; exists {
		if m, err := strconv.Atoi(fmt.Sprint(mtu)); err == nil {
			options.MTU = uint32(m)
		}
	}
	// Network
	if network, exists := config["network"]; exists {
		switch v := network.(type) {
		case string:
			options.Network = option.NetworkList(v)
		case []string:
			options.Network = option.NetworkList(strings.Join(v, ","))
		case []any:
			var nets []string
			for _, n := range v {
				if s, ok := n.(string); ok {
					nets = append(nets, s)
				}
			}
			if len(nets) > 0 {
				options.Network = option.NetworkList(strings.Join(nets, ","))
			}
		}
	}
	// Peers (for multi-peer configuration)
	if peers, exists := config["peers"].([]any); exists {
		for _, peer := range peers {
			if peerMap, ok := peer.(map[string]any); ok {
				wgPeer := option.LegacyWireGuardPeer{}

				if server, ok := peerMap["server"].(string); ok {
					wgPeer.Server = server
				}
				if port, ok := peerMap["port"]; ok {
					if p, err := strconv.Atoi(fmt.Sprint(port)); err == nil {
						wgPeer.ServerPort = uint16(p)
					}
				}
				if publicKey, ok := peerMap["public_key"].(string); ok {
					wgPeer.PublicKey = publicKey
				} else if publicKey, ok := peerMap["public-key"].(string); ok {
					wgPeer.PublicKey = publicKey
				}
				if preSharedKey, ok := peerMap["pre_shared_key"].(string); ok {
					wgPeer.PreSharedKey = preSharedKey
				} else if preSharedKey, ok := peerMap["pre-shared-key"].(string); ok {
					wgPeer.PreSharedKey = preSharedKey
				}
				if allowedIPs, ok := peerMap["allowed_ips"]; ok {
					wgPeer.AllowedIPs = parseAllowedIPs(allowedIPs)
				} else if allowedIPs, ok := peerMap["allowed-ips"]; ok {
					wgPeer.AllowedIPs = parseAllowedIPs(allowedIPs)
				}
				if reserved, ok := peerMap["reserved"]; ok {
					if bytes, err := parseReservedFromInterface(reserved); err == nil {
						wgPeer.Reserved = bytes
					}
				}
				options.Peers = append(options.Peers, wgPeer)
			}
		}
	}
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseWireGuardURL(wgURL string) (map[string]any, error) {
	config := make(map[string]any)

	// WireGuard URL format examples:
	// wg://[private_key]@[server]:[port]?publickey=[peer_public_key]&address=[local_address]&mtu=[mtu]#[name]
	// wireguard://[private_key]:[peer_public_key]:[pre_shared_key]@[server]:[port]?[params]#[name]

	if strings.HasPrefix(wgURL, "wireguard://") {
		wgURL = strings.TrimPrefix(wgURL, "wireguard://")
	} else if strings.HasPrefix(wgURL, "wg://") {
		wgURL = strings.TrimPrefix(wgURL, "wg://")
	} else {
		return nil, E.New("invalid WireGuard URL scheme")
	}

	// Extract name from fragment
	var name string
	if idx := strings.Index(wgURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(wgURL[idx+1:])
		wgURL = wgURL[:idx]
	}

	// Extract query parameters
	var queryPart string
	if idx := strings.Index(wgURL, "?"); idx != -1 {
		queryPart = wgURL[idx+1:]
		wgURL = wgURL[:idx]
	}

	// Extract keys and server
	atIndex := strings.LastIndex(wgURL, "@")
	if atIndex == -1 {
		return nil, E.New("missing '@' separator")
	}

	keysPart := wgURL[:atIndex]
	serverPart := wgURL[atIndex+1:]

	// Parse keys part
	// Format 1: private_key
	// Format 2: private_key:peer_public_key
	// Format 3: private_key:peer_public_key:pre_shared_key
	keys := strings.Split(keysPart, ":")
	if len(keys) >= 1 {
		config["private_key"] = keys[0]
	}
	if len(keys) >= 2 && keys[1] != "" {
		config["peer_public_key"] = keys[1]
	}
	if len(keys) >= 3 && keys[2] != "" {
		config["pre_shared_key"] = keys[2]
	}

	// Parse server:port
	var server string
	var portStr string

	if strings.HasPrefix(serverPart, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(serverPart, "]:"); idx != -1 {
			server = serverPart[1:idx]
			portStr = serverPart[idx+2:]
		} else if strings.HasSuffix(serverPart, "]") {
			// IPv6 [::1]
			server = serverPart[1 : len(serverPart)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		lastColonIdx := strings.LastIndex(serverPart, ":")
		if lastColonIdx != -1 {
			server = serverPart[:lastColonIdx]
			portStr = serverPart[lastColonIdx+1:]
		} else {
			server = serverPart
			portStr = ""
		}
	}

	config["server"] = server
	if portStr == "" {
		config["port"] = 51820 // Default WireGuard port
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	}

	// Parse query parameters
	if queryPart != "" {
		if err := parseWireGuardQueryParams(queryPart, &config); err != nil {
			return nil, err
		}
	}

	// Set name
	if name == "" {
		config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
	} else {
		config["name"] = name
	}

	// Validate required fields
	if config["server"] == nil || config["port"] == nil {
		return nil, E.New("missing server or port")
	}
	if config["private_key"] == nil {
		return nil, E.New("missing private key")
	}

	return config, nil
}

func parseWireGuardQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)
		value = betterdecode.DecodeURIComponent(value)

		switch key {
		// Keys
		case "privatekey", "private_key", "private-key", "privkey":
			(*config)["private_key"] = value
		case "publickey", "public_key", "public-key", "pubkey", "peer_public_key", "peer-public-key":
			(*config)["peer_public_key"] = value
		case "presharedkey", "pre_shared_key", "pre-shared-key", "psk":
			(*config)["pre_shared_key"] = value

		// Addresses
		case "address", "addresses", "local_address", "local-address":
			// Support comma-separated addresses
			addresses := strings.Split(value, ",")
			for i, addr := range addresses {
				addresses[i] = strings.TrimSpace(addr)
			}
			(*config)["local_address"] = addresses
		case "allowed_ips", "allowed-ips", "allowedips":
			// For allowed IPs (usually for peers)
			ips := strings.Split(value, ",")
			for i, ip := range ips {
				ips[i] = strings.TrimSpace(ip)
			}
			(*config)["allowed_ips"] = ips

		// Interface options
		case "system_interface", "system-interface":
			(*config)["system_interface"] = value == "1" || value == "true" || value == ""
		case "gso":
			(*config)["gso"] = value == "1" || value == "true" || value == ""
		case "interface_name", "interface-name", "ifname":
			(*config)["interface_name"] = value

		// WireGuard specific
		case "reserved":
			if bytes, err := parseReservedBytes(value); err == nil {
				(*config)["reserved"] = bytes
			}
		case "workers":
			if w, err := strconv.Atoi(value); err == nil {
				(*config)["workers"] = w
			}
		case "mtu":
			if m, err := strconv.Atoi(value); err == nil {
				(*config)["mtu"] = m
			}
		case "network", "net":
			networks := strings.Split(value, ",")
			for i, n := range networks {
				networks[i] = strings.TrimSpace(n)
			}
			(*config)["network"] = networks

		// Dialer options
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			(*config)["tcp-fast-open"] = value == "1" || value == "true" || value == ""
		case "bind-interface", "bind_interface", "interface":
			(*config)["bind-interface"] = value
		case "routing-mark", "routing_mark", "mark":
			if mark, err := strconv.Atoi(value); err == nil {
				(*config)["routing-mark"] = mark
			}
		case "reuse-addr", "reuse_addr":
			(*config)["reuse-addr"] = value == "1" || value == "true" || value == ""
		case "connect-timeout", "connect_timeout", "timeout":
			(*config)["connect-timeout"] = value
		case "tcp-keep-alive", "tcp_keep_alive", "keepalive":
			(*config)["tcp-keep-alive"] = value
		case "udp-fragment", "udp_fragment":
			(*config)["udp-fragment"] = value == "1" || value == "true" || value == ""
		case "domain-strategy", "domain_strategy":
			(*config)["domain-strategy"] = value
		case "fallback-delay", "fallback_delay":
			(*config)["fallback-delay"] = value
		}
	}

	// Set defaults
	if (*config)["local_address"] == nil {
		// Common default for WireGuard VPN
		(*config)["local_address"] = []string{"10.0.0.2/32"}
	}

	if (*config)["mtu"] == nil {
		(*config)["mtu"] = 1420 // Default WireGuard MTU
	}

	return nil
}

func parseReservedBytes(s string) ([]uint8, error) {
	s = strings.TrimSpace(s)

	// Support multiple formats
	// Format 1: comma-separated decimal: "0,0,0"
	// Format 2: hex string: "000000" or "0x000000"
	// Format 3: base64: "AAAA"

	// Try comma-separated first
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		var bytes []uint8
		for _, part := range parts {
			if b, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				bytes = append(bytes, uint8(b))
			} else {
				return nil, err
			}
		}
		return bytes, nil
	}

	// Try hex
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if bytes, err := hex.DecodeString(s); err == nil && len(bytes) == 3 {
		return bytes, nil
	}

	// Try base64
	if bytes, err := base64.StdEncoding.DecodeString(s); err == nil && len(bytes) == 3 {
		return bytes, nil
	}

	// Try as space-separated
	parts := strings.Fields(s)
	if len(parts) == 3 {
		var bytes []uint8
		for _, part := range parts {
			if b, err := strconv.Atoi(part); err == nil {
				bytes = append(bytes, uint8(b))
			} else {
				return nil, err
			}
		}
		return bytes, nil
	}

	return nil, E.New("invalid reserved bytes format")
}

func parseReservedFromInterface(v any) ([]uint8, error) {
	switch val := v.(type) {
	case string:
		return parseReservedBytes(val)
	case []uint8:
		return val, nil
	case []int:
		var bytes []uint8
		for _, b := range val {
			bytes = append(bytes, uint8(b))
		}
		return bytes, nil
	case []any:
		var bytes []uint8
		for _, item := range val {
			switch b := item.(type) {
			case float64:
				bytes = append(bytes, uint8(b))
			case int:
				bytes = append(bytes, uint8(b))
			}
		}
		return bytes, nil
	}
	return nil, E.New("unsupported reserved bytes type")
}

func parseAllowedIPs(v any) []netip.Prefix {
	var prefixes []netip.Prefix
	switch val := v.(type) {
	case string:
		for _, ip := range strings.Split(val, ",") {
			ip = strings.TrimSpace(ip)
			if prefix, err := netip.ParsePrefix(ip); err == nil {
				prefixes = append(prefixes, prefix)
			} else if addr, err := netip.ParseAddr(ip); err == nil {
				// Convert single IP to prefix
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				prefix := netip.PrefixFrom(addr, bits)
				prefixes = append(prefixes, prefix)
			}
		}
	case []string:
		for _, ip := range val {
			if prefix, err := netip.ParsePrefix(ip); err == nil {
				prefixes = append(prefixes, prefix)
			} else if addr, err := netip.ParseAddr(ip); err == nil {
				// Convert single IP to prefix
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				prefix := netip.PrefixFrom(addr, bits)
				prefixes = append(prefixes, prefix)
			}
		}
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok {
				if prefix, err := netip.ParsePrefix(s); err == nil {
					prefixes = append(prefixes, prefix)
				} else if addr, err := netip.ParseAddr(s); err == nil {
					// Convert single IP to prefix
					bits := 32
					if addr.Is6() {
						bits = 128
					}
					prefix := netip.PrefixFrom(addr, bits)
					prefixes = append(prefixes, prefix)
				}
			}
		}
	}
	return prefixes
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
