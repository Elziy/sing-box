package http

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func NewHTTPNativeOutboundOption(content string) (option.Outbound, error) {
	httpURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseHTTPURL(httpURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewHTTPOutboundOption(config)
}

func NewHTTPOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeHTTP,
	}
	options := &option.HTTPOutboundOptions{}
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
	// Authentication
	if username, exists := config["username"].(string); exists {
		options.Username = username
	}
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}
	// Path
	if path, exists := config["path"].(string); exists {
		options.Path = path
	}
	// Headers
	if headers, exists := config["headers"]; exists {
		httpHeaders := make(badoption.HTTPHeader)
		switch v := headers.(type) {
		case map[string]any:
			for key, value := range v {
				switch val := value.(type) {
				case string:
					httpHeaders[key] = badoption.Listable[string]{val}
				case []string:
					httpHeaders[key] = val
				case []any:
					var strList badoption.Listable[string]
					for _, item := range val {
						if str, ok := item.(string); ok {
							strList = append(strList, str)
						}
					}
					if len(strList) > 0 {
						httpHeaders[key] = strList
					}
				case badoption.Listable[string]:
					httpHeaders[key] = val
				}
			}
		}
		if len(httpHeaders) > 0 {
			options.Headers = httpHeaders
		}
	}
	options.TLS = option.NewOutboundTLSOptions(config)
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseHTTPURL(httpURL string) (map[string]any, error) {
	config := make(map[string]any)

	// Support both http:// and https:// schemes
	var isHTTPS bool
	if strings.HasPrefix(httpURL, "https://") {
		isHTTPS = true
		config["tls"] = true
	} else if !strings.HasPrefix(httpURL, "http://") {
		// Try to add http:// prefix if no scheme
		if !strings.Contains(httpURL, "://") {
			httpURL = "http://" + httpURL
		}
	}

	// Parse URL
	parsedURL, err := url.Parse(httpURL)
	if err != nil {
		// Fallback to manual parsing
		return parseHTTPURLManual(httpURL)
	}

	// Extract server and port
	config["server"] = parsedURL.Hostname()

	if parsedURL.Port() != "" {
		port, err := strconv.Atoi(parsedURL.Port())
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	} else {
		if isHTTPS {
			config["port"] = 443
		} else {
			config["port"] = 80
		}
	}

	// Extract authentication
	if parsedURL.User != nil {
		config["username"] = parsedURL.User.Username()
		if password, hasPassword := parsedURL.User.Password(); hasPassword {
			config["password"] = password
		}
	}

	// Extract path
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		config["path"] = parsedURL.Path
	}

	// Parse query parameters
	if parsedURL.RawQuery != "" {
		if err := parseHTTPQueryParams(parsedURL.RawQuery, &config); err != nil {
			return nil, err
		}
	}

	// Parse fragment for name
	if parsedURL.Fragment != "" {
		config["name"] = betterdecode.DecodeURIComponent(parsedURL.Fragment)
	} else {
		config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
	}

	// Validate required fields
	if config["server"] == nil || config["port"] == nil {
		return nil, E.New("missing required fields")
	}

	return config, nil
}

func parseHTTPURLManual(httpURL string) (map[string]any, error) {
	config := make(map[string]any)

	// Remove scheme
	if strings.HasPrefix(httpURL, "https://") {
		config["tls"] = true
		httpURL = strings.TrimPrefix(httpURL, "https://")
	} else if strings.HasPrefix(httpURL, "http://") {
		httpURL = strings.TrimPrefix(httpURL, "http://")
	}

	// Extract name from fragment
	var name string
	if idx := strings.Index(httpURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(httpURL[idx+1:])
		httpURL = httpURL[:idx]
	}

	// Extract query parameters
	var queryPart string
	if idx := strings.Index(httpURL, "?"); idx != -1 {
		queryPart = httpURL[idx+1:]
		httpURL = httpURL[:idx]
	}

	// Extract path
	var path string
	if idx := strings.Index(httpURL, "/"); idx != -1 {
		path = httpURL[idx:]
		httpURL = httpURL[:idx]
		if path != "/" {
			config["path"] = path
		}
	}

	// Extract authentication
	atIndex := strings.LastIndex(httpURL, "@")
	if atIndex != -1 {
		authPart := httpURL[:atIndex]
		serverPart := httpURL[atIndex+1:]

		// Parse authentication
		if colonIndex := strings.Index(authPart, ":"); colonIndex != -1 {
			config["username"] = authPart[:colonIndex]
			config["password"] = authPart[colonIndex+1:]
		} else {
			config["username"] = authPart
		}

		httpURL = serverPart
	}

	// Parse server:port
	var server string
	var portStr string

	if strings.HasPrefix(httpURL, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(httpURL, "]:"); idx != -1 {
			server = httpURL[1:idx]
			portStr = httpURL[idx+2:]
		} else if strings.HasSuffix(httpURL, "]") {
			// IPv6 [::1]
			server = httpURL[1 : len(httpURL)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		lastColonIdx := strings.LastIndex(httpURL, ":")
		if lastColonIdx != -1 && !strings.Contains(httpURL[lastColonIdx+1:], "]") {
			server = httpURL[:lastColonIdx]
			portStr = httpURL[lastColonIdx+1:]
		} else {
			server = httpURL
			portStr = ""
		}
	}

	config["server"] = server

	// Set port
	if portStr == "" {
		if config["tls"] != nil {
			config["port"] = 443
		} else {
			config["port"] = 80
		}
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	}

	// Parse query parameters
	if queryPart != "" {
		if err := parseHTTPQueryParams(queryPart, &config); err != nil {
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

func parseHTTPQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	headers := make(map[string]any)

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)
		value = betterdecode.DecodeURIComponent(value)

		switch key {
		// Authentication
		case "username", "user":
			(*config)["username"] = value
		case "password", "pass", "pwd":
			(*config)["password"] = value

		// Path
		case "path":
			(*config)["path"] = value

		// Headers - common header shortcuts
		case "host", "Host":
			headers["Host"] = []string{value}
		case "user-agent", "User-Agent", "ua":
			headers["User-Agent"] = []string{value}
		case "authorization", "Authorization", "auth":
			headers["Authorization"] = []string{value}
		case "proxy-authorization", "Proxy-Authorization":
			headers["Proxy-Authorization"] = []string{value}
		case "content-type", "Content-Type":
			headers["Content-Type"] = []string{value}
		case "accept", "Accept":
			headers["Accept"] = []string{value}
		case "accept-encoding", "Accept-Encoding":
			headers["Accept-Encoding"] = []string{value}
		case "accept-language", "Accept-Language":
			headers["Accept-Language"] = []string{value}
		case "referer", "Referer":
			headers["Referer"] = []string{value}
		case "origin", "Origin":
			headers["Origin"] = []string{value}
		case "cookie", "Cookie":
			headers["Cookie"] = []string{value}
		case "x-forwarded-for", "X-Forwarded-For", "xff":
			headers["X-Forwarded-For"] = []string{value}
		case "x-real-ip", "X-Real-IP":
			headers["X-Real-IP"] = []string{value}

		// Generic header format: header_Name=value or h_Name=value
		default:
			if strings.HasPrefix(key, "header_") || strings.HasPrefix(key, "h_") {
				var headerName string
				if strings.HasPrefix(key, "header_") {
					headerName = strings.TrimPrefix(key, "header_")
				} else {
					headerName = strings.TrimPrefix(key, "h_")
				}
				// Convert underscore to hyphen for standard headers
				headerName = strings.ReplaceAll(headerName, "_", "-")
				headers[headerName] = []string{value}
			} else {
				// TLS options
				switch key {
				case "tls", "secure", "https":
					(*config)["tls"] = value == "1" || value == "true" || value == ""
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
				case "insecure", "allowInsecure", "skipCertVerify", "skip-cert-verify":
					(*config)["tls"] = true
					(*config)["skip-cert-verify"] = value == "1" || value == "true" || value == ""
				case "fp", "fingerprint", "client-fingerprint":
					(*config)["tls"] = true
					(*config)["client-fingerprint"] = value
				case "ca", "ca-str":
					(*config)["tls"] = true
					(*config)["ca-str"] = []string{value}
				case "cert", "certificate":
					(*config)["tls"] = true
					(*config)["certificate"] = value
				case "key", "certificate-key":
					(*config)["tls"] = true
					(*config)["certificate-key"] = value

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
				case "udp-fragment", "udp_fragment":
					(*config)["udp-fragment"] = value == "1" || value == "true" || value == ""
				case "domain-strategy", "domain_strategy":
					(*config)["domain-strategy"] = value
				case "fallback-delay", "fallback_delay":
					(*config)["fallback-delay"] = value
				}
			}
		}
	}

	// Set headers if any were parsed
	if len(headers) > 0 {
		if existingHeaders, exists := (*config)["headers"].(map[string]any); exists {
			// Merge with existing headers
			for k, v := range headers {
				existingHeaders[k] = v
			}
		} else {
			(*config)["headers"] = headers
		}
	}

	// Set TLS SNI default if TLS is enabled but SNI is not set
	if (*config)["tls"] != nil && (*config)["sni"] == nil {
		(*config)["sni"] = (*config)["server"]
	}

	// Set default ALPN for HTTP proxy if TLS is enabled
	if (*config)["tls"] != nil && (*config)["alpn"] == nil {
		(*config)["alpn"] = []any{[]string{"h2", "http/1.1"}}
	}

	return nil
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
