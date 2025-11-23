package option

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

type _V2RayTransportOptions struct {
	Type               string                  `json:"type"`
	HTTPOptions        V2RayHTTPOptions        `json:"-"`
	WebsocketOptions   V2RayWebsocketOptions   `json:"-"`
	QUICOptions        V2RayQUICOptions        `json:"-"`
	GRPCOptions        V2RayGRPCOptions        `json:"-"`
	HTTPUpgradeOptions V2RayHTTPUpgradeOptions `json:"-"`
}

type V2RayTransportOptions _V2RayTransportOptions

func (o V2RayTransportOptions) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = o.HTTPUpgradeOptions
	case "":
		return nil, E.New("missing transport type")
	default:
		return nil, E.New("unknown transport type: " + o.Type)
	}
	return badjson.MarshallObjects((_V2RayTransportOptions)(o), v)
}

func (o *V2RayTransportOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_V2RayTransportOptions)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = &o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = &o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = &o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = &o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = &o.HTTPUpgradeOptions
	default:
		return E.New("unknown transport type: " + o.Type)
	}
	err = badjson.UnmarshallExcluded(bytes, (*_V2RayTransportOptions)(o), v)
	if err != nil {
		return err
	}
	return nil
}

type V2RayHTTPOptions struct {
	Host        badoption.Listable[string] `json:"host,omitempty"`
	Path        string                     `json:"path,omitempty"`
	Method      string                     `json:"method,omitempty"`
	Headers     badoption.HTTPHeader       `json:"headers,omitempty"`
	IdleTimeout badoption.Duration         `json:"idle_timeout,omitempty"`
	PingTimeout badoption.Duration         `json:"ping_timeout,omitempty"`
}

func NewV2RayHTTPOptions(proxy map[string]any) V2RayHTTPOptions {
	options := V2RayHTTPOptions{
		Host:    badoption.Listable[string]{},
		Headers: badoption.HTTPHeader{},
	}
	if httpOpts, exists := proxy["http-opts"].(map[string]any); exists {
		if method, exists := httpOpts["method"].(string); exists {
			options.Method = method
		}
		if pathRaw, exists := httpOpts["path"]; exists {
			switch path := pathRaw.(type) {
			case []string:
				options.Path = path[0]
			case string:
				options.Path = path
			}
		}
		if hostsRaw, exists := httpOpts["host"]; exists {
			switch hosts := hostsRaw.(type) {
			case []string:
				options.Host = hosts
			case string:
				options.Host = []string{hosts}
			}
		}
		if headers, exists := httpOpts["headers"].(map[string]any); exists {
			for key, valueRaw := range headers {
				var valueArr []string
				switch value := valueRaw.(type) {
				case []any:
					for _, item := range value {
						valueArr = append(valueArr, fmt.Sprint(item))
					}
				default:
					valueArr = append(valueArr, fmt.Sprint(value))
				}
				options.Headers[key] = valueArr
			}
		}
	}
	return options
}

type V2RayWebsocketOptions struct {
	Path                string               `json:"path,omitempty"`
	Headers             badoption.HTTPHeader `json:"headers,omitempty"`
	MaxEarlyData        uint32               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string               `json:"early_data_header_name,omitempty"`
}

func NewV2RayWebsocketOptions(config map[string]any) V2RayWebsocketOptions {
	options := V2RayWebsocketOptions{
		Headers: badoption.HTTPHeader{},
	}
	if wsOpts, exists := config["ws-opts"].(map[string]any); exists {
		if path, exists := wsOpts["path"].(string); exists {
			reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d+))?$`)
			result := reg.FindStringSubmatch(path)
			if result != nil {
				options.Path = result[1]
				if result[2] != "" {
					options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
					intNum, _ := strconv.Atoi(result[2])
					options.MaxEarlyData = uint32(intNum)
				}
			}
		}
		if maxEarlyData, exists := wsOpts["max-early-data"].(int); exists {
			options.MaxEarlyData = uint32(maxEarlyData)
		}
		if headers, exists := wsOpts["headers"].(map[string]any); exists {
			for key, valueRaw := range headers {
				var valueArr []string
				switch value := valueRaw.(type) {
				case []any:
					for _, item := range value {
						valueArr = append(valueArr, fmt.Sprint(item))
					}
				default:
					valueArr = append(valueArr, fmt.Sprint(value))
				}
				options.Headers[key] = valueArr
			}
		}
		if maxEarlyData, exists := wsOpts["max-early-data"].(int); exists {
			options.MaxEarlyData = uint32(maxEarlyData)
		}
		if earlyDataHeaderName, exists := wsOpts["early-data-header-name"].(string); exists {
			options.EarlyDataHeaderName = earlyDataHeaderName
		}
	}
	if path, exists := config["ws-path"].(string); exists {
		reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d+))?$`)
		result := reg.FindStringSubmatch(path)
		if result != nil {
			options.Path = result[1]
			if result[2] != "" {
				options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				intNum, _ := strconv.Atoi(result[2])
				options.MaxEarlyData = uint32(intNum)
			}
		}

	}
	if headers, exists := config["ws-headers"].(map[string]any); exists {
		for key, valueRaw := range headers {
			var valueArr []string
			switch value := valueRaw.(type) {
			case []any:
				for _, item := range value {
					valueArr = append(valueArr, fmt.Sprint(item))
				}
			default:
				valueArr = append(valueArr, fmt.Sprint(value))
			}
			options.Headers[key] = valueArr
		}
	}
	return options
}

type V2RayQUICOptions struct{}

func NewV2RayQUICOptions(config map[string]any) V2RayQUICOptions {
	return V2RayQUICOptions{}
}

type V2RayGRPCOptions struct {
	ServiceName         string             `json:"service_name,omitempty"`
	IdleTimeout         badoption.Duration `json:"idle_timeout,omitempty"`
	PingTimeout         badoption.Duration `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool               `json:"permit_without_stream,omitempty"`
	ForceLite           bool               `json:"-"` // for test
}

func NewV2RayGRPCOptions(config map[string]any) V2RayGRPCOptions {
	options := V2RayGRPCOptions{}
	if grpcOpts, exists := config["grpc-opts"].(map[string]any); exists {
		if servername, exists := grpcOpts["grpc-service-name"].(string); exists {
			options.ServiceName = servername
		}
	}
	return options
}

type V2RayHTTPUpgradeOptions struct {
	Host    string               `json:"host,omitempty"`
	Path    string               `json:"path,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}

func NewV2RayHTTPUpgradeOptions(proxy map[string]any) V2RayHTTPUpgradeOptions {
	options := V2RayHTTPUpgradeOptions{
		Headers: badoption.HTTPHeader{},
	}
	wsOpts := proxy["ws-opts"].(map[string]any)
	if path, exists := wsOpts["path"].(string); exists {
		options.Path = path
	}
	if headers, exists := wsOpts["headers"].(map[string]any); exists {
		for key, valueRaw := range headers {
			var valueArr []string
			switch value := valueRaw.(type) {
			case []any:
				for _, item := range value {
					valueArr = append(valueArr, fmt.Sprint(item))
				}
			default:
				valueArr = append(valueArr, fmt.Sprint(value))
			}
			if strings.ToLower(key) == "host" {
				options.Host = valueArr[0]
				continue
			}
			options.Headers[key] = valueArr
		}
	}
	if path, exists := proxy["ws-path"].(string); exists {
		options.Path = path
	}
	if headers, exists := proxy["ws-headers"].(map[string]any); exists {
		for key, valueRaw := range headers {
			var valueArr []string
			switch value := valueRaw.(type) {
			case []any:
				for _, item := range value {
					valueArr = append(valueArr, fmt.Sprint(item))
				}
			default:
				valueArr = append(valueArr, fmt.Sprint(value))
			}
			if strings.ToLower(key) == "host" {
				options.Host = valueArr[0]
				continue
			}
			options.Headers[key] = valueArr
		}
	}
	return options
}
