package anytls

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func NewAnyTLSNativeOutboundOption(content string) (option.Outbound, error) {
	anyTlsURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseAnyTLSURL(anyTlsURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewAnyTLSOutboundOption(config)
}

func NewAnyTLSOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeAnyTLS,
	}
	options := &option.AnyTLSOutboundOptions{}
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
	// Password
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}
	// Idle Session Check Interval
	if interval, exists := config["idle_session_check_interval"]; exists {
		switch v := interval.(type) {
		case string:
			if duration, err := parseDuration(v); err == nil {
				options.IdleSessionCheckInterval = badoption.Duration(duration)
			}
		case int:
			options.IdleSessionCheckInterval = badoption.Duration(time.Duration(v) * time.Second)
		case badoption.Duration:
			options.IdleSessionCheckInterval = v
		}
	} else if interval, exists := config["idle-session-check-interval"]; exists {
		switch v := interval.(type) {
		case string:
			if duration, err := parseDuration(v); err == nil {
				options.IdleSessionCheckInterval = badoption.Duration(duration)
			}
		case int:
			options.IdleSessionCheckInterval = badoption.Duration(time.Duration(v) * time.Second)
		case badoption.Duration:
			options.IdleSessionCheckInterval = v
		}
	}

	// Idle Session Timeout
	if timeout, exists := config["idle_session_timeout"]; exists {
		switch v := timeout.(type) {
		case string:
			if duration, err := parseDuration(v); err == nil {
				options.IdleSessionTimeout = badoption.Duration(duration)
			}
		case int:
			options.IdleSessionTimeout = badoption.Duration(time.Duration(v) * time.Second)
		case badoption.Duration:
			options.IdleSessionTimeout = v
		}
	} else if timeout, exists := config["idle-session-timeout"]; exists {
		switch v := timeout.(type) {
		case string:
			if duration, err := parseDuration(v); err == nil {
				options.IdleSessionTimeout = badoption.Duration(duration)
			}
		case int:
			options.IdleSessionTimeout = badoption.Duration(time.Duration(v) * time.Second)
		case badoption.Duration:
			options.IdleSessionTimeout = v
		}
	}

	// Min Idle Session
	if minIdleSession, exists := config["min_idle_session"]; exists {
		if mis, err := strconv.Atoi(fmt.Sprint(minIdleSession)); err == nil {
			options.MinIdleSession = mis
		}
	} else if minIdleSession, exists := config["min-idle-session"]; exists {
		if mis, err := strconv.Atoi(fmt.Sprint(minIdleSession)); err == nil {
			options.MinIdleSession = mis
		}
	}
	// TLS options (AnyTLS always uses TLS)
	options.TLS = option.NewOutboundTLSOptions(config)
	options.DialerOptions = option.NewDialerOption(config)
	outbound.Options = options
	return outbound, nil
}

func parseAnyTLSURL(anyTlsURL string) (map[string]any, error) {
	config := make(map[string]any)

	// AnyTLS URL format: anytls://[password]@[server]:[port]?[params]#[name]
	// or: anytls://[server]:[port]?password=[password]&[params]#[name]

	// Support both anytls:// and at:// schemes
	if strings.HasPrefix(anyTlsURL, "anytls://") {
		anyTlsURL = strings.TrimPrefix(anyTlsURL, "anytls://")
		config["tls"] = true
	} else if strings.HasPrefix(anyTlsURL, "at://") {
		anyTlsURL = strings.TrimPrefix(anyTlsURL, "at://")
		config["tls"] = true
	} else if strings.HasPrefix(anyTlsURL, "https://") {
		// Support HTTPS scheme for AnyTLS
		parsedURL, err := url.Parse("https://" + anyTlsURL)
		if err != nil {
			return parseAnyTLSURLManual(anyTlsURL, config)
		}
		return parseAnyTLSFromURL(parsedURL, config)
	} else if !strings.Contains(anyTlsURL, "://") {
		// No scheme, assume anytls
		config["tls"] = true
	} else {
		// Try to parse as URL
		parsedURL, err := url.Parse(anyTlsURL)
		if err != nil {
			return nil, E.New("invalid AnyTLS URL format")
		}
		if parsedURL.Scheme != "anytls" && parsedURL.Scheme != "at" && parsedURL.Scheme != "https" {
			return nil, E.New("unsupported scheme: ", parsedURL.Scheme)
		}
		return parseAnyTLSFromURL(parsedURL, config)
	}

	return parseAnyTLSURLManual(anyTlsURL, config)
}

func parseAnyTLSFromURL(parsedURL *url.URL, config map[string]any) (map[string]any, error) {
	// AnyTLS always uses TLS
	config["tls"] = true

	// Extract server and port
	config["server"] = parsedURL.Hostname()

	if parsedURL.Port() != "" {
		port, err := strconv.Atoi(parsedURL.Port())
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	} else {
		config["port"] = 443 // Default HTTPS/TLS port
	}

	// Extract password from user info
	if parsedURL.User != nil {
		password := parsedURL.User.Username()
		if password == "" {
			// Try to get from password field
			password, _ = parsedURL.User.Password()
		}
		if password != "" {
			config["password"] = password
		}
	}

	// Parse query parameters
	if parsedURL.RawQuery != "" {
		if err := parseAnyTLSQueryParams(parsedURL.RawQuery, &config); err != nil {
			return nil, err
		}
	}

	// Parse fragment for name
	if parsedURL.Fragment != "" {
		config["name"] = betterdecode.DecodeURIComponent(parsedURL.Fragment)
	} else {
		config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
	}

	// Set default SNI if not specified
	if config["sni"] == nil {
		config["sni"] = config["server"]
	}

	return config, nil
}

func parseAnyTLSURLManual(anyTlsURL string, config map[string]any) (map[string]any, error) {
	// Extract name from fragment
	var name string
	if idx := strings.Index(anyTlsURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(anyTlsURL[idx+1:])
		anyTlsURL = anyTlsURL[:idx]
	}

	// Extract query parameters
	var queryPart string
	if idx := strings.Index(anyTlsURL, "?"); idx != -1 {
		queryPart = anyTlsURL[idx+1:]
		anyTlsURL = anyTlsURL[:idx]
	}

	// Check for password in URL
	atIndex := strings.LastIndex(anyTlsURL, "@")
	if atIndex != -1 {
		passwordPart := anyTlsURL[:atIndex]
		serverPart := anyTlsURL[atIndex+1:]

		// The part before @ is the password
		config["password"] = passwordPart
		anyTlsURL = serverPart
	}

	// Parse server:port
	var server string
	var portStr string

	if strings.HasPrefix(anyTlsURL, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(anyTlsURL, "]:"); idx != -1 {
			server = anyTlsURL[1:idx]
			portStr = anyTlsURL[idx+2:]
		} else if strings.HasSuffix(anyTlsURL, "]") {
			// IPv6 [::1]
			server = anyTlsURL[1 : len(anyTlsURL)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		lastColonIdx := strings.LastIndex(anyTlsURL, ":")
		if lastColonIdx != -1 {
			server = anyTlsURL[:lastColonIdx]
			portStr = anyTlsURL[lastColonIdx+1:]
		} else {
			server = anyTlsURL
			portStr = ""
		}
	}

	config["server"] = server
	if portStr == "" {
		config["port"] = 443 // Default TLS port
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	}

	// Parse query parameters
	if queryPart != "" {
		if err := parseAnyTLSQueryParams(queryPart, &config); err != nil {
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

	return config, nil
}

func parseAnyTLSQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)
		value = betterdecode.DecodeURIComponent(value)

		switch key {
		// Authentication
		case "password", "pass", "pwd":
			(*config)["password"] = value

		// Session management
		case "idle_session_check_interval", "idle-session-check-interval", "check_interval", "check-interval":
			// Parse duration: support formats like "10s", "30s", "1m"
			if duration, err := parseDuration(value); err == nil {
				(*config)["idle_session_check_interval"] = duration.String()
			} else if intVal, err := strconv.Atoi(value); err == nil {
				// If plain number, treat as seconds
				(*config)["idle_session_check_interval"] = fmt.Sprintf("%ds", intVal)
			} else {
				(*config)["idle_session_check_interval"] = value
			}

		case "idle_session_timeout", "idle-session-timeout", "session_timeout", "session-timeout":
			// Parse duration
			if duration, err := parseDuration(value); err == nil {
				(*config)["idle_session_timeout"] = duration.String()
			} else if intVal, err := strconv.Atoi(value); err == nil {
				// If plain number, treat as seconds
				(*config)["idle_session_timeout"] = fmt.Sprintf("%ds", intVal)
			} else {
				(*config)["idle_session_timeout"] = value
			}

		case "min_idle_session", "min-idle-session", "min_session", "min-session":
			if mis, err := strconv.Atoi(value); err == nil {
				(*config)["min_idle_session"] = mis
			}

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
		case "ech", "enable_ech", "enable-ech":
			(*config)["ech"] = value == "1" || value == "true" || value == ""
		case "ech_config", "ech-config":
			(*config)["ech-config"] = []string{value}
		case "ech_key", "ech-key":
			(*config)["ech-key"] = []string{value}
		case "utls", "utls_imitate", "utls-imitate":
			(*config)["utls"] = value
		case "reality", "enable_reality", "enable-reality":
			(*config)["reality"] = value == "1" || value == "true" || value == ""
		case "pbk", "public_key", "public-key":
			if (*config)["reality-opts"] == nil {
				(*config)["reality-opts"] = make(map[string]any)
			}
			(*config)["reality-opts"].(map[string]any)["public-key"] = value
		case "sid", "short_id", "short-id":
			if (*config)["reality-opts"] == nil {
				(*config)["reality-opts"] = make(map[string]any)
			}
			(*config)["reality-opts"].(map[string]any)["short-id"] = value

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

	// Set defaults for session management if not specified
	if (*config)["idle_session_check_interval"] == nil {
		(*config)["idle_session_check_interval"] = "30s"
	}

	if (*config)["idle_session_timeout"] == nil {
		(*config)["idle_session_timeout"] = "300s" // 5 minutes
	}

	if (*config)["min_idle_session"] == nil {
		(*config)["min_idle_session"] = 1
	}

	// Set default ALPN for AnyTLS if not specified
	if (*config)["alpn"] == nil {
		(*config)["alpn"] = []any{[]string{"h2", "http/1.1"}}
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
