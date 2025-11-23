package shadowsocks

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewShadowsocksNativeOutboundOption(content string) (option.Outbound, error) {
	shadowsocksURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseShadowsocksURL(shadowsocksURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewShadowsocksOutboundOption(config)
}

func NewShadowsocksOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeShadowsocks,
	}
	options := &option.ShadowsocksOutboundOptions{
		Multiplex: &option.OutboundMultiplexOptions{},
	}
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
	if method, exists := config["cipher"].(string); exists {
		options.Method = method
	}
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}
	if plugin, exists := config["plugin"].(string); exists {
		var optArr []string
		switch plugin {
		case "obfs", "obfs-local":
			options.Plugin = "obfs-local"
			if opts, exists := config["plugin-opts"].(map[string]any); exists {
				for key, value := range opts {
					switch key {
					case "mode":
						optArr = append(optArr, fmt.Sprint("obfs=", value))
					case "host":
						optArr = append(optArr, fmt.Sprint("obfs-host=", value))
					default:
						optArr = append(optArr, fmt.Sprint(key, "=", value))
					}
				}
			}
		case "v2ray", "v2ray-plugin":
			options.Plugin = "v2ray-plugin"
			if opts, exists := config["plugin-opts"].(map[string]any); exists {
				for key, value := range opts {
					switch key {
					case "mode":
						optArr = append(optArr, fmt.Sprint("obfs=", value))
					case "host":
						host := value
						if h, ok := config["ws-host"].(string); ok {
							host = h
						}
						optArr = append(optArr, fmt.Sprint("host=", host))
					case "path":
						path := value
						if p, ok := config["ws-path"].(string); ok {
							path = p
						}
						optArr = append(optArr, fmt.Sprint("path=", path))
					case "headers":
						headers, _ := value.(map[string]any)
						data, _ := json.Marshal(headers)
						optArr = append(optArr, fmt.Sprint("headers", "=", string(data)))
					case "mux":
						if mux, _ := value.(bool); mux {
							options.Multiplex.Enabled = true
						}
					default:
						optArr = append(optArr, fmt.Sprint(key, "=", value))
					}
				}
			}
		}
		options.PluginOptions = strings.Join(optArr, ";")
	}
	if uot, exists := config["uot"].(bool); exists && uot {
		options.UDPOverTCP = &option.UDPOverTCPOptions{
			Enabled: true,
		}
	}
	if uot, exists := config["udp-over-tcp"].(bool); exists && uot {
		options.UDPOverTCP = &option.UDPOverTCPOptions{
			Enabled: true,
		}
	}
	options.DialerOptions = option.NewDialerOption(config)
	options.Multiplex = option.NewOutboundMultiplexOptions(config)
	outbound.Options = options
	return outbound, nil
}

func parseShadowsocksURL(shadowsocksURL string) (map[string]any, error) {
	config := make(map[string]any)

	shadowsocksURL = strings.TrimPrefix(shadowsocksURL, "ss://")

	var name string
	if idx := strings.Index(shadowsocksURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(shadowsocksURL[idx+1:])
		shadowsocksURL = shadowsocksURL[:idx]
	}

	var queryPart string
	if idx := strings.Index(shadowsocksURL, "/?"); idx != -1 {
		queryPart = shadowsocksURL[idx+2:] // skip /?
		shadowsocksURL = shadowsocksURL[:idx]
	} else if idx := strings.Index(shadowsocksURL, "?"); idx != -1 {
		queryPart = shadowsocksURL[idx+1:]
		shadowsocksURL = shadowsocksURL[:idx]
	}

	shadowsocksURL = betterdecode.DecodeBase64Safe(shadowsocksURL)
	atIndex := strings.LastIndex(shadowsocksURL, "@")
	if atIndex == -1 {
		return nil, E.New("missing @ separator")
	}
	authPart := betterdecode.DecodeBase64Safe(shadowsocksURL[:atIndex])
	serverPart := betterdecode.DecodeBase64Safe(shadowsocksURL[atIndex+1:])

	// method:password
	colonIndex := strings.Index(authPart, ":")
	if colonIndex == -1 {
		return nil, E.New("missing ':' in auth part")
	}
	config["cipher"] = authPart[:colonIndex]
	config["password"] = authPart[colonIndex+1:]

	// server:port
	colonIndex = strings.LastIndex(serverPart, ":")
	if colonIndex == -1 {
		return nil, E.New("missing ':' in server part")
	}
	config["server"] = serverPart[:colonIndex]
	portStr := serverPart[colonIndex+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, E.New(fmt.Sprintf("invalid port: %v", err))
	}
	config["port"] = port

	if config["server"] == nil || config["port"] == nil || config["cipher"] == nil || config["password"] == nil {
		return nil, E.New("missing required fields")
	}

	if queryPart != "" {
		_ = parseShadowsocksQueryParams(queryPart, &config)
	}

	if name == "" {
		config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
	} else {
		config["name"] = name
	}

	return config, nil
}

func parseShadowsocksQueryParams(shadowsocksQueryParams string, config *map[string]any) error {
	pluginOptions := make(map[string]any)
	params := strings.Split(shadowsocksQueryParams, "&")
	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)
		switch key {
		case "plugin":
			if strings.Contains(value, ";") {
				parts := strings.Split(value, ";")
				(*config)["plugin"] = parts[0]
				for i := 1; i < len(parts); i++ {
					optKey, optValue := splitKeyValueWithEqual(parts[i])
					if optKey != "" {
						if optValue == "" || optValue == "1" || optValue == "true" {
							pluginOptions[optKey] = true
						} else {
							pluginOptions[optKey] = optValue
						}
					}
				}
			} else {
				(*config)["plugin"] = value
			}
		default:
			switch key {
			case "uot", "udp-over-tcp", "udp_over_tcp":
				(*config)["uot"] = value == "" || value == "1" || value == "true"
			case "tfo", "tcp-fast-open", "tcp_fast_open":
				(*config)["tcp_fast_open"] = value == "" || value == "1" || value == "true"
			default:
				if key != "" {
					if value == "" {
						(*config)[key] = true
					} else {
						(*config)[key] = value
					}
				}
			}
		}
	}
	(*config)["plugin-opts"] = pluginOptions
	return nil
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
