package hysteria

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewHysteriaNativeOutboundOption(content string) (option.Outbound, error) {
	hysteriaURL := betterdecode.DecodeBase64Safe(content)

	config, err := parseHysteriaURL(hysteriaURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewHysteriaOutboundOption(config)
}

func NewHysteriaOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeHysteria,
	}
	options := &option.HysteriaOutboundOptions{}
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
	if authStr, exists := config["auth-str"]; exists {
		options.AuthString = fmt.Sprint(authStr)
	}
	if authStr, exists := config["auth_str"]; exists {
		options.AuthString = fmt.Sprint(authStr)
	}
	if upRaw, exists := config["up"]; exists {
		switch up := upRaw.(type) {
		case string:
			networkBytes := &byteformats.NetworkBytesCompat{}
			if err := networkBytes.UnmarshalJSON([]byte(`"` + up + `"`)); err == nil {
				options.Up = networkBytes
			}
		case int:
			options.UpMbps = up
		}
	}
	if downRaw, exists := config["down"]; exists {
		switch down := downRaw.(type) {
		case string:
			networkBytes := &byteformats.NetworkBytesCompat{}
			if err := networkBytes.UnmarshalJSON([]byte(`"` + down + `"`)); err == nil {
				options.Down = networkBytes
			}
		case int:
			options.DownMbps = down
		}
	}
	if obfs, exists := config["obfs"].(string); exists {
		options.Obfs = obfs
	}
	if recvWindowConn, exists := config["recv-window-conn"].(int); exists {
		options.ReceiveWindowConn = uint64(recvWindowConn)
	}
	if recvWindowConn, exists := config["recv_window_conn"].(int); exists {
		options.ReceiveWindowConn = uint64(recvWindowConn)
	}
	if recvWindow, exists := config["recv-window"].(int); exists {
		options.ReceiveWindow = uint64(recvWindow)
	}
	if recvWindow, exists := config["recv_window"].(int); exists {
		options.ReceiveWindow = uint64(recvWindow)
	}
	if disable, exists := config["disable-mtu-discovery"].(bool); exists && disable {
		options.DisableMTUDiscovery = true
	}
	if disable, exists := config["disable_mtu_discovery"].(bool); exists && disable {
		options.DisableMTUDiscovery = true
	}
	if network, exists := config["network"].(string); exists {
		options.Network = option.NetworkList(network)
	}
	options.TLS = option.NewOutboundTLSOptions(config)
	options.TLS.UTLS.Enabled = false
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseHysteriaURL(hysteriaURL string) (map[string]any, error) {
	config := make(map[string]any)

	hysteriaURL = strings.TrimPrefix(hysteriaURL, "hysteria://")
	hysteriaURL = strings.TrimPrefix(hysteriaURL, "hy://")

	var name string
	if idx := strings.Index(hysteriaURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(hysteriaURL[idx+1:])
		hysteriaURL = hysteriaURL[:idx]
	}

	var queryPart string
	if idx := strings.Index(hysteriaURL, "?"); idx != -1 {
		queryPart = hysteriaURL[idx+1:]
		hysteriaURL = hysteriaURL[:idx]
	}

	var authPart string
	if idx := strings.Index(hysteriaURL, "@"); idx != -1 {
		authPart = hysteriaURL[:idx]
		hysteriaURL = hysteriaURL[idx+1:]
		// username:password
		if colonIdx := strings.Index(authPart, ":"); colonIdx != -1 {
			config["auth-str"] = authPart[colonIdx+1:]
		} else {
			// username only
			config["auth-str"] = authPart
		}
	}

	var server string
	var portStr string
	if strings.HasPrefix(hysteriaURL, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(hysteriaURL, "]:"); idx != -1 {
			server = hysteriaURL[1:idx]
			portStr = hysteriaURL[idx+2:]
		} else if strings.HasSuffix(hysteriaURL, "]") {
			// IPv6 without port
			server = hysteriaURL[1 : len(hysteriaURL)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		// IPv4 or domain
		lastColonIdx := strings.LastIndex(hysteriaURL, ":")
		if lastColonIdx != -1 {
			server = hysteriaURL[:lastColonIdx]
			portStr = hysteriaURL[lastColonIdx+1:]
		} else {
			server = hysteriaURL
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

	if config["server"] == nil || config["port"] == nil || config["auth-str"] == nil {
		return nil, E.New("missing required fields")
	}

	if queryPart != "" {
		if err := parseHysteriaQueryParams(queryPart, &config); err != nil {
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

func parseHysteriaQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)

		switch key {
		case "auth", "authstr":
			(*config)["auth-str"] = value
		case "up", "upmbps":
			up, err := strconv.Atoi(value)
			if err != nil {
				(*config)["up"] = value
			} else {
				(*config)["up"] = up
			}
		case "down", "downmbps":
			down, err := strconv.Atoi(value)
			if err != nil {
				(*config)["down"] = value
			} else {
				(*config)["down"] = down
			}
		case "obfs":
			if (*config)["obfs"] != nil {
				(*config)["obfs"] = value
			}
		case "obfsparam", "obfsParam":
			(*config)["obfs"] = value
		case "network", "protocol":
			(*config)["network"] = value
		case "recv_window_conn":
			if rwc, err := strconv.ParseUint(value, 10, 64); err == nil {
				(*config)["recv-window-conn"] = rwc
			}
		case "recv_window":
			if rw, err := strconv.ParseUint(value, 10, 64); err == nil {
				(*config)["recv-window"] = rw
			}
		case "disable_mtu_discovery":
			if value == "1" || value == "true" || value == "" {
				(*config)["disable-mtu-discovery"] = true
			}

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

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
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
