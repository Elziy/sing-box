package socks

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewSOCKSNativeOutboundOption(content string) (option.Outbound, error) {
	socksURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseSOCKSURL(socksURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewSOCKSOutboundOption(config)
}

func NewSOCKSOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeSOCKS,
	}
	options := &option.SOCKSOutboundOptions{}
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
	if version, exists := config["version"].(string); exists {
		options.Version = version
	} else {
		// default 5
		options.Version = "5"
	}
	if username, exists := config["username"].(string); exists {
		options.Username = username
	}
	if password, exists := config["password"].(string); exists {
		options.Password = password
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

	// UDP over TCP
	if udpOverTCP, exists := config["udp-over-tcp"]; exists {
		switch v := udpOverTCP.(type) {
		case bool:
			if v {
				options.UDPOverTCP = &option.UDPOverTCPOptions{
					Enabled: true,
				}
			}
		case map[string]any:
			uotOptions := &option.UDPOverTCPOptions{}
			if enabled, ok := v["enabled"].(bool); ok {
				uotOptions.Enabled = enabled
			}
			if version, ok := v["version"].(uint8); ok {
				uotOptions.Version = version
			}
			options.UDPOverTCP = uotOptions
		}
	}
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseSOCKSURL(socksURL string) (map[string]any, error) {
	config := make(map[string]any)

	var version string
	if strings.HasPrefix(socksURL, "socks5://") {
		version = "5"
		socksURL = strings.TrimPrefix(socksURL, "socks5://")
	} else if strings.HasPrefix(socksURL, "socks4a://") {
		version = "4a"
		socksURL = strings.TrimPrefix(socksURL, "socks4a://")
	} else if strings.HasPrefix(socksURL, "socks4://") {
		version = "4"
		socksURL = strings.TrimPrefix(socksURL, "socks4://")
	} else if strings.HasPrefix(socksURL, "socks://") {
		version = "5" // Default to socks5
		socksURL = strings.TrimPrefix(socksURL, "socks://")
	} else {
		// Try to parse as standard URL
		parsedURL, err := url.Parse(socksURL)
		if err != nil {
			return nil, E.New("invalid SOCKS URL format")
		}

		switch parsedURL.Scheme {
		case "socks5":
			version = "5"
		case "socks4a":
			version = "4a"
		case "socks4":
			version = "4"
		case "socks":
			version = "5"
		default:
			return nil, E.New("unsupported scheme: ", parsedURL.Scheme)
		}

		// Extract from parsed URL
		if parsedURL.User != nil {
			config["username"] = parsedURL.User.Username()
			if password, hasPassword := parsedURL.User.Password(); hasPassword {
				config["password"] = password
			}
		}

		config["server"] = parsedURL.Hostname()
		if parsedURL.Port() != "" {
			port, err := strconv.Atoi(parsedURL.Port())
			if err != nil {
				return nil, E.New("invalid port: ", err)
			}
			config["port"] = port
		} else {
			config["port"] = 1080 // Default SOCKS port
		}

		config["version"] = version

		// Parse query parameters
		if parsedURL.RawQuery != "" {
			if err := parseSOCKSQueryParams(parsedURL.RawQuery, &config); err != nil {
				return nil, err
			}
		}

		// Parse fragment for name
		if parsedURL.Fragment != "" {
			config["name"] = betterdecode.DecodeURIComponent(parsedURL.Fragment)
		} else {
			config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
		}

		return config, nil
	}

	// Manual parsing for non-standard URLs
	var name string
	if idx := strings.Index(socksURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(socksURL[idx+1:])
		socksURL = socksURL[:idx]
	}

	var queryPart string
	if idx := strings.Index(socksURL, "?"); idx != -1 {
		queryPart = socksURL[idx+1:]
		socksURL = socksURL[:idx]
	}

	// Check for authentication: [username[:password]@]server:port
	atIndex := strings.LastIndex(socksURL, "@")
	if atIndex != -1 {
		authPart := socksURL[:atIndex]
		serverPart := socksURL[atIndex+1:]

		// Parse authentication
		if colonIndex := strings.Index(authPart, ":"); colonIndex != -1 {
			config["username"] = authPart[:colonIndex]
			config["password"] = authPart[colonIndex+1:]
		} else {
			config["username"] = authPart
		}

		socksURL = serverPart
	}

	var server string
	var portStr string

	if strings.HasPrefix(socksURL, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(socksURL, "]:"); idx != -1 {
			server = socksURL[1:idx]
			portStr = socksURL[idx+2:]
		} else if strings.HasSuffix(socksURL, "]") {
			// IPv6 [::1]
			server = socksURL[1 : len(socksURL)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		lastColonIdx := strings.LastIndex(socksURL, ":")
		if lastColonIdx != -1 {
			server = socksURL[:lastColonIdx]
			portStr = socksURL[lastColonIdx+1:]
		} else {
			server = socksURL
			portStr = ""
		}
	}

	config["server"] = server
	if portStr == "" {
		config["port"] = 1080 // Default SOCKS port
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	}

	config["version"] = version

	// Parse query parameters
	if queryPart != "" {
		if err := parseSOCKSQueryParams(queryPart, &config); err != nil {
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
		return nil, E.New("missing required fields")
	}

	return config, nil
}

func parseSOCKSQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)

		switch key {
		// Version
		case "version", "v":
			(*config)["version"] = value

		// Authentication
		case "username", "user":
			(*config)["username"] = value
		case "password", "pass", "pwd":
			(*config)["password"] = value

		// Network
		case "network", "net":
			// Support comma-separated values like "tcp,udp"
			networks := strings.Split(value, ",")
			for i, n := range networks {
				networks[i] = strings.TrimSpace(n)
			}
			(*config)["network"] = networks

		// UDP over TCP
		case "uot", "udp-over-tcp", "udp_over_tcp":
			if value == "1" || value == "true" || value == "" {
				(*config)["udp-over-tcp"] = true
			}
		case "uot_version", "udp-over-tcp-version":
			if version, err := strconv.Atoi(value); err == nil {
				if (*config)["udp-over-tcp"] == nil {
					(*config)["udp-over-tcp"] = make(map[string]any)
				}
				switch v := (*config)["udp-over-tcp"].(type) {
				case map[string]any:
					v["version"] = uint8(version)
				case bool:
					(*config)["udp-over-tcp"] = map[string]any{
						"enabled": v,
						"version": uint8(version),
					}
				}
			}

		// Dialer options
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			(*config)["tcp-fast-open"] = value == "1" || value == "true" || value == ""
		case "mptcp", "multi-path":
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
		}
	}
	return nil
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
