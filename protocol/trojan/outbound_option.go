package trojan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func NewTrojanNativeOutboundOption(content string) (option.Outbound, error) {
	trojanURL := betterdecode.DecodeBase64Safe(content)

	config, err := parseTrojanURL(trojanURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewTrojanOutboundOption(config)
}

func NewTrojanOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeTrojan,
	}
	options := &option.TrojanOutboundOptions{}
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
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}
	if network, exists := config["network"].(string); exists {
		Transport := option.V2RayTransportOptions{}
		switch network {
		case "ws":
			Transport.Type = C.V2RayTransportTypeWebsocket
			Transport.WebsocketOptions = option.NewV2RayWebsocketOptions(config)
		case "httpupgrade":
			Transport.Type = C.V2RayTransportTypeHTTPUpgrade
			Transport.HTTPUpgradeOptions = option.NewV2RayHTTPUpgradeOptions(config)
		case "http":
			Transport.Type = C.V2RayTransportTypeHTTP
			Transport.HTTPOptions = option.NewV2RayHTTPOptions(config)
		case "grpc":
			Transport.Type = C.V2RayTransportTypeGRPC
			Transport.GRPCOptions = option.NewV2RayGRPCOptions(config)
		case "quic":
			Transport.Type = C.V2RayTransportTypeQUIC
			Transport.QUICOptions = option.NewV2RayQUICOptions(config)
		}
		options.Transport = &Transport
	}
	options.TLS = option.NewOutboundTLSOptions(config)
	options.DialerOptions = option.NewDialerOption(config)
	options.Multiplex = option.NewOutboundMultiplexOptions(config)
	outbound.Options = options
	return outbound, nil
}

func parseTrojanURL(trojanURL string) (map[string]any, error) {
	config := make(map[string]any)

	trojanURL = strings.TrimPrefix(trojanURL, "trojan://")

	var name string
	if idx := strings.Index(trojanURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(trojanURL[idx+1:])
		trojanURL = trojanURL[:idx]
	}

	var queryPart string
	if idx := strings.Index(trojanURL, "?"); idx != -1 {
		queryPart = trojanURL[idx+1:]
		trojanURL = trojanURL[:idx]
	}

	// password@server:port
	atIndex := strings.Index(trojanURL, "@")
	if atIndex == -1 {
		return nil, E.New("missing '@' separator")
	}
	config["password"] = trojanURL[:atIndex]
	serverPart := trojanURL[atIndex+1:]

	var server string
	var portStr string
	if strings.HasPrefix(serverPart, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(serverPart, "]:"); idx != -1 {
			server = serverPart[1:idx] // skip '['
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
		// IPv4 server:port
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
		config["port"] = 443
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New(fmt.Sprintf("invalid port: %v", err))
		}
		config["port"] = port
	}

	if config["server"] == nil || config["port"] == nil || config["password"] == nil {
		return nil, E.New("missing required fields")
	}

	if queryPart != "" {
		if err := parseTrojanQueryParams(queryPart, &config); err != nil {
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

func parseTrojanQueryParams(trojanQueryParams string, config *map[string]any) error {
	params := strings.Split(trojanQueryParams, "&")

	smux := make(map[string]any)
	brutal := make(map[string]any)

	transport := make(map[string]any)

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)

		switch key {
		// mux
		case "mux", "multiplex":
			if value == "1" || value == "true" || value == "" {
				smux["enabled"] = true
				(*config)["smux"] = smux
			}
		case "mux_protocol", "multiplex_protocol":
			smux["protocol"] = value
		case "mux_max_connections", "max_connections":
			if maxConn, err := strconv.Atoi(value); err == nil {
				smux["max-connections"] = maxConn
			}
		case "mux_min_streams", "min_streams":
			if minStreams, err := strconv.Atoi(value); err == nil {
				smux["min-streams"] = minStreams
			}
		case "mux_max_streams", "max_streams":
			if maxStreams, err := strconv.Atoi(value); err == nil {
				smux["max-streams"] = maxStreams
			}
		case "mux_padding", "padding":
			if value == "1" || value == "true" {
				smux["padding"] = true
			}
		case "brutal":
			if value == "1" || value == "true" || value == "" {
				brutal["enabled"] = true
				(*config)["brutal"] = brutal
			}
		case "brutal_up", "up_mbps":
			if upMbps, err := strconv.Atoi(value); err == nil {
				brutal["up-mbps"] = upMbps
			}
		case "brutal_down", "down_mbps":
			if downMbps, err := strconv.Atoi(value); err == nil {
				brutal["down-mbps"] = downMbps
			}

		// transport
		case "type", "transport":
			switch value {
			case "tcp":
				(*config)["network"] = "tcp"
			case "ws", "websocket":
				(*config)["network"] = "ws"
			case "h2", "http":
				(*config)["network"] = "http"
			case "grpc":
				(*config)["network"] = "grpc"
			case "quic":
				(*config)["network"] = "quic"
			default:
				(*config)["network"] = "tcp"
			}
		case "path":
			transport["path"] = value
		case "host":
			switch (*config)["network"] {
			case "ws", "httpupgrade":
				if _, ok := transport["headers"]; !ok {
					transport["headers"] = make(map[string]any)
				}
				transport["headers"].(map[string]any)["Host"] = []string{value}
			default:
				transport["host"] = badoption.Listable[string]{value}
			}
		//	ws
		case "ed":
			if ed, err := strconv.Atoi(value); err == nil {
				transport["max-early-data"] = ed
			}
		//	http
		case "method":
			transport["method"] = value
		// grpc
		case "serviceName", "service-name", "service_name":
			transport["grpc-service-name"] = value

		// TLS
		case "sni":
			(*config)["tls"] = true
			(*config)["sni"] = value
		case "alpn":
			alpnList := strings.Split(value, ",")
			for i, a := range alpnList {
				alpnList[i] = strings.TrimSpace(a)
			}
			(*config)["tls"] = true
			(*config)["alpn"] = []any{alpnList}
		case "insecure", "allowInsecure", "skipCertVerify":
			(*config)["tls"] = true
			(*config)["skip-cert-verify"] = value == "1" || value == "true" || value == ""

		// dialer
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			(*config)["tcp-fast-open"] = true
		case "uot", "udp-over-tcp", "udp_over_tcp":
			(*config)["udp-over-tcp"] = true
		}
	}

	// transport default tls
	if (*config)["network"] != nil && (*config)["tls"] == nil {
		(*config)["tls"] = true
		(*config)["sni"] = (*config)["server"]
	}

	// tls default sni
	if (*config)["tls"] != nil && (*config)["sni"] == nil {
		(*config)["sni"] = (*config)["server"]
	}

	switch (*config)["network"] {
	case "ws", "httpupgrade":
		(*config)["ws-opts"] = transport
	case "http":
		(*config)["http-opts"] = transport
	case "grpc":
		(*config)["grpc-opts"] = transport
	case "quic":
		(*config)["quic-opts"] = transport
	}

	return nil
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
