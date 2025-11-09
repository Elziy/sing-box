package option

type InboundMultiplexOptions struct {
	Enabled bool           `json:"enabled,omitempty"`
	Padding bool           `json:"padding,omitempty"`
	Brutal  *BrutalOptions `json:"brutal,omitempty"`
}

type OutboundMultiplexOptions struct {
	Enabled        bool           `json:"enabled,omitempty"`
	Protocol       string         `json:"protocol,omitempty"`
	MaxConnections int            `json:"max_connections,omitempty"`
	MinStreams     int            `json:"min_streams,omitempty"`
	MaxStreams     int            `json:"max_streams,omitempty"`
	Padding        bool           `json:"padding,omitempty"`
	Brutal         *BrutalOptions `json:"brutal,omitempty"`
}

type BrutalOptions struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

func NewOutboundMultiplexOptions(config map[string]any) *OutboundMultiplexOptions {
	options := OutboundMultiplexOptions{
		Enabled: false,
	}
	smux, exists := config["smux"].(map[string]any)
	if !exists {
		return &options
	}
	if enabled, exists := smux["enabled"].(bool); exists {
		options.Enabled = enabled
	}
	if protocol, exists := smux["protocol"].(string); exists {
		options.Protocol = protocol
	}
	if maxConnections, exists := smux["max-connections"].(int); exists {
		options.MaxConnections = maxConnections
	}
	if maxStreams, exists := smux["max-streams"].(int); exists {
		options.MaxStreams = maxStreams
	}
	if minStreams, exists := smux["min-streams"].(int); exists {
		options.MinStreams = minStreams
	}
	if padding, exists := smux["padding"].(bool); exists {
		options.Padding = padding
	}
	if brutal, exists := smux["brutal"].(map[string]any); exists {
		options.Brutal = &BrutalOptions{}
		if enabled, exists := brutal["enabled"].(bool); exists {
			options.Brutal.Enabled = enabled
		}
		if upMbps, exists := brutal["up-mbps"].(int); exists {
			options.Brutal.UpMbps = upMbps
		}
		if downMbps, exists := brutal["down-mbps"].(int); exists {
			options.Brutal.DownMbps = downMbps
		}
	}
	return &options
}
