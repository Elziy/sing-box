package ssh

import (
	"encoding/base64"
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

func NewSSHNativeOutboundOption(content string) (option.Outbound, error) {
	sshURL := betterdecode.DecodeBase64Safe(content)
	config, err := parseSSHURL(sshURL)
	if err != nil {
		return option.Outbound{}, err
	}
	return NewSSHOutboundOption(config)
}

func NewSSHOutboundOption(config map[string]any) (option.Outbound, error) {
	outbound := option.Outbound{
		Type: C.TypeSSH,
	}
	options := &option.SSHOutboundOptions{}

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

	// User
	if user, exists := config["user"].(string); exists {
		options.User = user
	} else if user, exists := config["username"].(string); exists {
		options.User = user
	}

	// Password
	if password, exists := config["password"].(string); exists {
		options.Password = password
	}

	// Private Key
	if privateKey, exists := config["private_key"]; exists {
		switch v := privateKey.(type) {
		case string:
			options.PrivateKey = badoption.Listable[string]{v}
		case []string:
			options.PrivateKey = v
		case []any:
			var keys badoption.Listable[string]
			for _, item := range v {
				if key, ok := item.(string); ok {
					keys = append(keys, key)
				}
			}
			if len(keys) > 0 {
				options.PrivateKey = keys
			}
		case badoption.Listable[string]:
			options.PrivateKey = v
		}
	} else if privateKey, exists := config["private-key"]; exists {
		switch v := privateKey.(type) {
		case string:
			options.PrivateKey = badoption.Listable[string]{v}
		case []string:
			options.PrivateKey = v
		case []any:
			var keys badoption.Listable[string]
			for _, item := range v {
				if key, ok := item.(string); ok {
					keys = append(keys, key)
				}
			}
			if len(keys) > 0 {
				options.PrivateKey = keys
			}
		}
	}

	// Private Key Path
	if privateKeyPath, exists := config["private_key_path"].(string); exists {
		options.PrivateKeyPath = privateKeyPath
	} else if privateKeyPath, exists := config["private-key-path"].(string); exists {
		options.PrivateKeyPath = privateKeyPath
	}

	// Private Key Passphrase
	if passphrase, exists := config["private_key_passphrase"].(string); exists {
		options.PrivateKeyPassphrase = passphrase
	} else if passphrase, exists := config["private-key-passphrase"].(string); exists {
		options.PrivateKeyPassphrase = passphrase
	}

	// Host Key
	if hostKey, exists := config["host_key"]; exists {
		switch v := hostKey.(type) {
		case string:
			options.HostKey = badoption.Listable[string]{v}
		case []string:
			options.HostKey = v
		case []any:
			var keys badoption.Listable[string]
			for _, item := range v {
				if key, ok := item.(string); ok {
					keys = append(keys, key)
				}
			}
			if len(keys) > 0 {
				options.HostKey = keys
			}
		case badoption.Listable[string]:
			options.HostKey = v
		}
	} else if hostKey, exists := config["host-key"]; exists {
		switch v := hostKey.(type) {
		case string:
			options.HostKey = badoption.Listable[string]{v}
		case []string:
			options.HostKey = v
		case []any:
			var keys badoption.Listable[string]
			for _, item := range v {
				if key, ok := item.(string); ok {
					keys = append(keys, key)
				}
			}
			if len(keys) > 0 {
				options.HostKey = keys
			}
		}
	}

	// Host Key Algorithms
	if algorithms, exists := config["host_key_algorithms"]; exists {
		switch v := algorithms.(type) {
		case string:
			// Split comma-separated algorithms
			algos := strings.Split(v, ",")
			for i, algo := range algos {
				algos[i] = strings.TrimSpace(algo)
			}
			options.HostKeyAlgorithms = algos
		case []string:
			options.HostKeyAlgorithms = v
		case []any:
			var algos badoption.Listable[string]
			for _, item := range v {
				if algo, ok := item.(string); ok {
					algos = append(algos, algo)
				}
			}
			if len(algos) > 0 {
				options.HostKeyAlgorithms = algos
			}
		case badoption.Listable[string]:
			options.HostKeyAlgorithms = v
		}
	} else if algorithms, exists := config["host-key-algorithms"]; exists {
		switch v := algorithms.(type) {
		case string:
			algos := strings.Split(v, ",")
			for i, algo := range algos {
				algos[i] = strings.TrimSpace(algo)
			}
			options.HostKeyAlgorithms = algos
		case []string:
			options.HostKeyAlgorithms = v
		case []any:
			var algos badoption.Listable[string]
			for _, item := range v {
				if algo, ok := item.(string); ok {
					algos = append(algos, algo)
				}
			}
			if len(algos) > 0 {
				options.HostKeyAlgorithms = algos
			}
		}
	}

	// Client Version
	if clientVersion, exists := config["client_version"].(string); exists {
		options.ClientVersion = clientVersion
	} else if clientVersion, exists := config["client-version"].(string); exists {
		options.ClientVersion = clientVersion
	}

	// Dialer options
	options.DialerOptions = option.NewDialerOption(config)

	outbound.Options = options
	return outbound, nil
}

func parseSSHURL(sshURL string) (map[string]any, error) {
	config := make(map[string]any)

	// SSH URL format:
	// ssh://[user[:password]@]server[:port][?params][#name]
	// ssh://[user@]server[:port][?params][#name] (with private key in params)

	if !strings.HasPrefix(sshURL, "ssh://") {
		// Try to parse as standard URL by adding ssh:// prefix
		if !strings.Contains(sshURL, "://") {
			sshURL = "ssh://" + sshURL
		} else {
			return nil, E.New("unsupported URL scheme, expected ssh://")
		}
	}

	parsedURL, err := url.Parse(sshURL)
	if err != nil {
		// Fallback to manual parsing
		return parseSSHURLManual(sshURL)
	}

	if parsedURL.Scheme != "ssh" {
		return nil, E.New("unsupported scheme: ", parsedURL.Scheme)
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
		config["port"] = 22 // Default SSH port
	}

	// Extract user info
	if parsedURL.User != nil {
		config["user"] = parsedURL.User.Username()
		if password, hasPassword := parsedURL.User.Password(); hasPassword {
			config["password"] = password
		}
	}

	// Parse query parameters
	if parsedURL.RawQuery != "" {
		if err := parseSSHQueryParams(parsedURL.RawQuery, &config); err != nil {
			return nil, err
		}
	}

	// Parse fragment for name
	if parsedURL.Fragment != "" {
		config["name"] = betterdecode.DecodeURIComponent(parsedURL.Fragment)
	} else {
		if user, exists := config["user"]; exists {
			config["name"] = fmt.Sprintf("%s@%s:%d", user, config["server"], config["port"])
		} else {
			config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
		}
	}

	// Validate required fields
	if config["server"] == nil || config["port"] == nil {
		return nil, E.New("missing server or port")
	}

	return config, nil
}

func parseSSHURLManual(sshURL string) (map[string]any, error) {
	config := make(map[string]any)

	sshURL = strings.TrimPrefix(sshURL, "ssh://")

	// Extract name from fragment
	var name string
	if idx := strings.Index(sshURL, "#"); idx != -1 {
		name = betterdecode.DecodeURIComponent(sshURL[idx+1:])
		sshURL = sshURL[:idx]
	}

	// Extract query parameters
	var queryPart string
	if idx := strings.Index(sshURL, "?"); idx != -1 {
		queryPart = sshURL[idx+1:]
		sshURL = sshURL[:idx]
	}

	// Extract user info: user[:password]@server:port
	atIndex := strings.LastIndex(sshURL, "@")
	if atIndex != -1 {
		userPart := sshURL[:atIndex]
		serverPart := sshURL[atIndex+1:]

		// Parse user info
		if colonIndex := strings.Index(userPart, ":"); colonIndex != -1 {
			config["user"] = userPart[:colonIndex]
			config["password"] = userPart[colonIndex+1:]
		} else {
			config["user"] = userPart
		}

		sshURL = serverPart
	}

	// Parse server:port
	var server string
	var portStr string

	if strings.HasPrefix(sshURL, "[") {
		// IPv6 [::1]:port
		if idx := strings.Index(sshURL, "]:"); idx != -1 {
			server = sshURL[1:idx]
			portStr = sshURL[idx+2:]
		} else if strings.HasSuffix(sshURL, "]") {
			// IPv6 [::1]
			server = sshURL[1 : len(sshURL)-1]
			portStr = ""
		} else {
			return nil, E.New("invalid IPv6 address format")
		}
	} else {
		lastColonIdx := strings.LastIndex(sshURL, ":")
		if lastColonIdx != -1 {
			server = sshURL[:lastColonIdx]
			portStr = sshURL[lastColonIdx+1:]
		} else {
			server = sshURL
			portStr = ""
		}
	}

	config["server"] = server
	if portStr == "" {
		config["port"] = 22 // Default SSH port
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, E.New("invalid port: ", err)
		}
		config["port"] = port
	}

	// Parse query parameters
	if queryPart != "" {
		if err := parseSSHQueryParams(queryPart, &config); err != nil {
			return nil, err
		}
	}

	// Set name
	if name == "" {
		if user, exists := config["user"]; exists {
			config["name"] = fmt.Sprintf("%s@%s:%d", user, config["server"], config["port"])
		} else {
			config["name"] = fmt.Sprintf("%s:%d", config["server"], config["port"])
		}
	} else {
		config["name"] = name
	}

	// Validate required fields
	if config["server"] == nil || config["port"] == nil {
		return nil, E.New("missing server or port")
	}

	return config, nil
}

func parseSSHQueryParams(queryPart string, config *map[string]any) error {
	params := strings.Split(queryPart, "&")

	var privateKeys []string
	var hostKeys []string
	var hostKeyAlgorithms []string

	for _, param := range params {
		key, value := splitKeyValueWithEqual(param)
		value = betterdecode.DecodeURIComponent(value)

		switch key {
		// Authentication
		case "user", "username":
			(*config)["user"] = value
		case "password", "pass", "pwd":
			(*config)["password"] = value

		// Private Key
		case "private_key", "private-key", "privkey", "key":
			// Support base64 encoded keys
			if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
				privateKeys = append(privateKeys, string(decoded))
			} else {
				privateKeys = append(privateKeys, value)
			}
		case "private_key_path", "private-key-path", "key_path", "key-path":
			(*config)["private_key_path"] = value
		case "private_key_passphrase", "private-key-passphrase", "passphrase", "key_passphrase", "key-passphrase":
			(*config)["private_key_passphrase"] = value

		// Host Key
		case "host_key", "host-key", "hostkey":
			// Support base64 encoded keys
			if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
				hostKeys = append(hostKeys, string(decoded))
			} else {
				hostKeys = append(hostKeys, value)
			}
		case "host_key_algorithms", "host-key-algorithms", "algorithms":
			// Support comma-separated algorithms
			algos := strings.Split(value, ",")
			for _, algo := range algos {
				algo = strings.TrimSpace(algo)
				if algo != "" {
					hostKeyAlgorithms = append(hostKeyAlgorithms, algo)
				}
			}

		// Client Version
		case "client_version", "client-version", "version":
			(*config)["client_version"] = value

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

	// Set collected arrays
	if len(privateKeys) > 0 {
		(*config)["private_key"] = privateKeys
	}
	if len(hostKeys) > 0 {
		(*config)["host_key"] = hostKeys
	}
	if len(hostKeyAlgorithms) > 0 {
		(*config)["host_key_algorithms"] = hostKeyAlgorithms
	}

	// Set default user if not specified
	if (*config)["user"] == nil {
		(*config)["user"] = "root"
	}

	// Set default client version if not specified
	if (*config)["client_version"] == nil {
		(*config)["client_version"] = "SSH-2.0-OpenSSH_8.9"
	}

	// Validate authentication method
	hasPassword := (*config)["password"] != nil
	hasPrivateKey := (*config)["private_key"] != nil || (*config)["private_key_path"] != nil

	if !hasPassword && !hasPrivateKey {
		// No authentication method specified, this might be intentional for some setups
		// but we should warn or set a default
		// For now, we'll allow it as some SSH servers might accept connections without auth
	}

	return nil
}

func splitKeyValueWithEqual(s string) (string, string) {
	if idx := strings.Index(s, "="); idx != -1 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
