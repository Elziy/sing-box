package hysteria2

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

func NewHysteria2NativeOutboundOption(content string) (option.Outbound, error) {
	hysteria2URL := betterdecode.DecodeBase64Safe(content)
	config, err := parseHysteria2URL(hysteria2URL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewHysteria2OutboundOption(config)
}

func NewHysteria2OutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeHysteria2,
	}
	options := &option.Hysteria2OutboundOptions{}
	obfsOptions := option.Hysteria2Obfs{}
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
	if ports, exists := config["server-ports"].([]string); exists {
		options.ServerPorts = ports
	}
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}
	if up, exists := config["up"].(int); exists {
		options.UpMbps = up
	}
	if down, exists := config["down"].(int); exists {
		options.DownMbps = down
	}
	if hopInterval, exists := config["hop-interval"].(string); exists {
		if duration, err := time.ParseDuration(hopInterval); err == nil {
			options.HopInterval = badoption.Duration(duration)
		} else if seconds, err := strconv.Atoi(hopInterval); err == nil {
			options.HopInterval = badoption.Duration(time.Duration(seconds) * time.Second)
		}
	}
	if obfs, exists := config["obfs"].(string); exists && obfs == "salamander" {
		obfsOptions.Type = obfs
	}
	if obfsPassword, exists := config["obfs-password"].(string); exists {
		obfsOptions.Password = obfsPassword
	}
	if obfsOptions.Type != "" {
		options.Obfs = &obfsOptions
	}
	options.TLS = option.NewOutboundTLSOptions(config)
	options.TLS.Enabled = true
	options.TLS.UTLS.Enabled = false
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseHysteria2URL(hysteria2URL string) (map[string]any, error) {
	config := make(map[string]any)

	hysteria2URL = strings.TrimPrefix(hysteria2URL, "hysteria2://")
	hysteria2URL = strings.TrimPrefix(hysteria2URL, "hy2://")

	var name string
	if idx := strings.Index(hysteria2URL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(hysteria2URL[idx+1:])
		hysteria2URL = hysteria2URL[:idx]
	}

	var queryPart string
	if idx := strings.Index(hysteria2URL, "?"); idx != -1 {
		queryPart = hysteria2URL[idx+1:]
		hysteria2URL = hysteria2URL[:idx]
	}

	var authPart string
	if idx := strings.Index(hysteria2URL, "@"); idx != -1 {
		authPart = hysteria2URL[:idx]
		hysteria2URL = hysteria2URL[idx+1:]
		if colonIdx := strings.Index(authPart, ":"); colonIdx != -1 {
			// user:password
			config["password"] = authPart[colonIdx+1:]
		} else {
			// password
			config["password"] = authPart
		}
	}

	var server string
	var portStr string

	if strings.HasPrefix(hysteria2URL, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(hysteria2URL, "]:"); idx != -1 {
			server = hysteria2URL[1:idx]
			portStr = hysteria2URL[idx+2:]
		} else if strings.HasSuffix(hysteria2URL, "]") {
			// IPv6 without port
			server = hysteria2URL[1 : len(hysteria2URL)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		// IPv4 or domain
		lastColonIdx := strings.LastIndex(hysteria2URL, ":")
		if lastColonIdx != -1 {
			server = hysteria2URL[:lastColonIdx]
			portStr = hysteria2URL[lastColonIdx+1:]
		} else {
			server = hysteria2URL
			portStr = ""
		}
	}

	config["server"] = server

	if portStr == "" {
		config["port"] = 443
	} else {
		// "port,port-port"
		if strings.Contains(portStr, ",") || strings.Contains(portStr, "-") {
			serverPorts := parseServerPorts(portStr)
			if len(serverPorts) > 0 {
				config["server-ports"] = serverPorts
				// first port as main port
				if firstPort, err := strconv.Atoi(strings.Split(serverPorts[0], "-")[0]); err == nil {
					config["port"] = firstPort
				} else {
					config["port"] = 443
				}
			} else {
				config["port"] = 443
			}
		} else {
			// single port
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, E.New(fmt.Sprintf("invalid port: %v", err))
			}
			config["port"] = port
		}
	}

	if config["server"] == nil || config["port"] == nil || config["password"] == nil {
		return nil, E.New("missing required fields")
	}

	if queryPart != "" {
		if err := parseHysteria2QueryParams(queryPart, &config); err != nil {
			return nil, err
		}
	}

	if name == "" {
		config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
	} else {
		config["name"] = name
	}

	return config, nil
}

func parseHysteria2QueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)

		switch key {
		case "password", "pass", "auth":
			(*config)["password"] = value
		case "up", "upmbps":
			if upMbps, err := strconv.Atoi(value); err == nil {
				(*config)["upMbps"] = upMbps
			}
		case "down", "downmbps":
			if downMbps, err := strconv.Atoi(value); err == nil {
				(*config)["downMbps"] = downMbps
			}
		case "hop_interval", "hopinterval":
			(*config)["hop-interval"] = value
		case "obfs":
			(*config)["obfs"] = value
		case "obfs-password", "obfsparam":
			(*config)["obfs-password"] = value
		case "network", "protocol":
			(*config)["network"] = value

		// sni
		case "sni", "peer":
			(*config)["tls"] = true
			(*config)["sni"] = value
		case "alpn":
			alpnList := strings.Split(value, ",")
			for i, a := range alpnList {
				alpnList[i] = strings.TrimSpace(a)
			}
			(*config)["tls"] = true
			(*config)["alpn"] = []any{alpnList}
		case "insecure":
			(*config)["tls"] = true
			(*config)["skip-cert-verify"] = value == "1" || value == "true" || value == ""
		}
	}

	// tls default sni
	if (*config)["tls"] != nil && (*config)["sni"] == nil {
		(*config)["sni"] = (*config)["server"]
	}

	return nil
}

func parseServerPorts(portStr string) []string {
	var serverPorts []string

	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// port range (e.g. "30000-40000")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				startStr := strings.TrimSpace(rangeParts[0])
				endStr := strings.TrimSpace(rangeParts[1])

				start, err1 := strconv.Atoi(startStr)
				end, err2 := strconv.Atoi(endStr)

				if err1 == nil && err2 == nil && start <= end && start > 0 && end <= 65535 {
					serverPorts = append(serverPorts, fmt.Sprintf("%d-%d", start, end))
				}
			}
		} else {
			// single port (e.g. "30000")
			if port, err := strconv.Atoi(part); err == nil && port > 0 && port <= 65535 {
				serverPorts = append(serverPorts, part)
			}
		}
	}

	return serverPorts
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
