package tuic

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func NewTUICNativeOutboundOption(content string) (option.Outbound, error) {
	tuicURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseTUICURL(tuicURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewTUICOutboundOption(config)
}

func NewTUICOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeTUIC,
	}
	options := &option.TUICOutboundOptions{}
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
	// UUID (required for TUIC)
	if uuid, exists := config["uuid"].(string); exists {
		options.UUID = uuid
	}
	// Password (alternative to UUID for some TUIC versions)
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}
	// Congestion Control
	if cc, exists := config["congestion_control"].(string); exists {
		options.CongestionControl = cc
	} else if cc, exists := config["congestion-controller"].(string); exists {
		options.CongestionControl = cc
	}
	// UDP Relay Mode
	if mode, exists := config["udp_relay_mode"].(string); exists {
		options.UDPRelayMode = mode
	} else if mode, exists := config["udp-relay-mode"].(string); exists {
		options.UDPRelayMode = mode
	}
	// UDP Over Stream
	if uos, exists := config["udp_over_stream"].(bool); exists {
		options.UDPOverStream = uos
	} else if uos, exists := config["udp-over-stream"].(bool); exists {
		options.UDPOverStream = uos
	}
	// Zero RTT Handshake
	if zRtt, exists := config["zero_rtt_handshake"].(bool); exists {
		options.ZeroRTTHandshake = zRtt
	} else if zRtt, exists := config["zero-rtt-handshake"].(bool); exists {
		options.ZeroRTTHandshake = zRtt
	} else if zRtt, exists := config["0rtt"].(bool); exists {
		options.ZeroRTTHandshake = zRtt
	} else if zRtt, exists := config["reduce-rtt"].(bool); exists {
		options.ZeroRTTHandshake = zRtt
	}
	// Heartbeat
	if heartbeat, exists := config["heartbeat"]; exists {
		switch v := heartbeat.(type) {
		case string:
			if duration, err := parseDuration(v); err == nil {
				options.Heartbeat = badoption.Duration(duration)
			}
		case int:
			options.Heartbeat = badoption.Duration(time.Duration(v) * time.Second)
		case badoption.Duration:
			options.Heartbeat = v
		}
	}
	if heartbeat, exists := config["heartbeat-interval"].(int); exists {
		if duration, err := time.ParseDuration(fmt.Sprint(heartbeat, "ms")); err == nil {
			options.Heartbeat = badoption.Duration(duration)
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
	options.TLS = option.NewOutboundTLSOptions(config)
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseTUICURL(tuicURL string) (map[string]any, error) {
	config := make(map[string]any)

	// TUIC URL format: tuic://[uuid]:[password]@[server]:[port]?[params]#[name]
	// or: tuic://[password]@[server]:[port]?[params]#[name]

	tuicURL = strings.TrimPrefix(tuicURL, "tuic://")

	// Extract name from fragment
	var name string
	if idx := strings.Index(tuicURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(tuicURL[idx+1:])
		tuicURL = tuicURL[:idx]
	}

	// Extract query parameters
	var queryPart string
	if idx := strings.Index(tuicURL, "?"); idx != -1 {
		queryPart = tuicURL[idx+1:]
		tuicURL = tuicURL[:idx]
	}

	// Extract authentication part (uuid:password or just password)
	atIndex := strings.LastIndex(tuicURL, "@")
	if atIndex == -1 {
		return nil, E.New("missing '@' separator")
	}

	authPart := tuicURL[:atIndex]
	serverPart := tuicURL[atIndex+1:]

	// Parse authentication
	if colonIndex := strings.Index(authPart, ":"); colonIndex != -1 {
		// UUID:Password format
		config["uuid"] = authPart[:colonIndex]
		config["password"] = authPart[colonIndex+1:]
	} else {
		// Just password format (for TUIC v5)
		config["password"] = authPart
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
		config["port"] = 443 // Default TUIC port (uses QUIC/TLS)
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	}

	// TUIC always uses TLS
	config["tls"] = true

	// Parse query parameters
	if queryPart != "" {
		if err := parseTUICQueryParams(queryPart, &config); err != nil {
			return nil, err
		}
	}

	// Set name
	if name == "" {
		config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
	} else {
		config["name"] = name
	}

	// Set default SNI if not specified
	if config["sni"] == nil {
		config["sni"] = config["server"]
	}

	// Validate required fields
	if config["server"] == nil || config["port"] == nil {
		return nil, E.New("missing server or port")
	}
	if config["uuid"] == nil && config["password"] == nil {
		return nil, E.New("missing UUID or password")
	}

	return config, nil
}

func parseTUICQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)
		value = betterdecode.DecodeURIComponent(value)

		switch key {
		// Authentication
		case "uuid":
			(*config)["uuid"] = value
		case "password", "passwd", "pwd":
			(*config)["password"] = value

		// TUIC specific options
		case "congestion_control", "congestion-control", "cc":
			(*config)["congestion_control"] = value
		case "udp_relay_mode", "udp-relay-mode", "udp_mode":
			// native, quic
			(*config)["udp_relay_mode"] = value
		case "udp_over_stream", "udp-over-stream", "uos":
			(*config)["udp_over_stream"] = value == "1" || value == "true" || value == ""
		case "zero_rtt_handshake", "zero-rtt-handshake", "0rtt", "zero_rtt", "zero-rtt":
			(*config)["zero_rtt_handshake"] = value == "1" || value == "true" || value == ""
		case "heartbeat", "heartbeat_interval":
			// Parse duration: support formats like "10s", "30s", "1m"
			if duration, err := parseDuration(value); err == nil {
				(*config)["heartbeat"] = duration.String()
			} else if intVal, err := strconv.Atoi(value); err == nil {
				// If plain number, treat as seconds
				(*config)["heartbeat"] = fmt.Sprintf("%ds", intVal)
			} else {
				(*config)["heartbeat"] = value
			}

		// Network
		case "network", "net":
			networks := strings.Split(value, ",")
			for i, n := range networks {
				networks[i] = strings.TrimSpace(n)
			}
			(*config)["network"] = networks

		// TLS options
		case "sni", "server_name":
			(*config)["sni"] = value
		case "alpn":
			alpnList := strings.Split(value, ",")
			for i, a := range alpnList {
				alpnList[i] = strings.TrimSpace(a)
			}
			(*config)["alpn"] = []any{alpnList}
		case "insecure", "allowInsecure", "skipCertVerify", "skip-cert-verify", "skip_cert_verify":
			(*config)["skip-cert-verify"] = value == "1" || value == "true" || value == ""
		case "disable_sni", "disable-sni":
			(*config)["disable-sni"] = value == "1" || value == "true" || value == ""
		case "fp", "fingerprint", "client-fingerprint", "client_fingerprint":
			(*config)["client-fingerprint"] = value
		case "ca", "ca-str", "ca_str":
			(*config)["ca-str"] = []string{value}
		case "cert", "certificate":
			(*config)["certificate"] = value
		case "key", "certificate-key", "certificate_key":
			(*config)["certificate-key"] = value

		// QUIC specific options
		case "max_open_streams", "max-open-streams":
			if val, err := strconv.Atoi(value); err == nil {
				(*config)["max-open-streams"] = val
			}
		case "max_datagram_frame_size", "max-datagram-frame-size":
			if val, err := strconv.Atoi(value); err == nil {
				(*config)["max-datagram-frame-size"] = val
			}

		// Dialer options
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			(*config)["tcp-fast-open"] = value == "1" || value == "true" || value == ""
		case "mptcp", "multi-path", "multi_path":
			(*config)["mptcp"] = value == "1" || value == "true" || value == ""
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
		case "tcp-keep-alive-interval", "keepalive_interval":
			(*config)["tcp-keep-alive-interval"] = value
		case "domain-strategy", "domain_strategy":
			(*config)["domain-strategy"] = value
		case "fallback-delay", "fallback_delay":
			(*config)["fallback-delay"] = value
		}
	}

	// Set default congestion control if not specified
	if (*config)["congestion_control"] == nil {
		(*config)["congestion_control"] = "cubic"
	}

	// Set default UDP relay mode if not specified
	if (*config)["udp_relay_mode"] == nil {
		(*config)["udp_relay_mode"] = "native"
	}

	// Set default ALPN for TUIC if not specified
	if (*config)["alpn"] == nil {
		(*config)["alpn"] = []any{[]string{"h3"}}
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	// Support formats: "30s", "5m", "1h", "100ms", etc.
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}

	// If it's just a number, treat it as seconds
	if v, err := strconv.Atoi(s); err == nil {
		return time.Duration(v) * time.Second, nil
	}

	// Try parsing as standard duration string
	return time.ParseDuration(s)
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
