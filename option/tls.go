package option

import (
	"fmt"

	"github.com/sagernet/sing/common/json/badoption"
)

type InboundTLSOptions struct {
	Enabled         bool                       `json:"enabled,omitempty"`
	ServerName      string                     `json:"server_name,omitempty"`
	Insecure        bool                       `json:"insecure,omitempty"`
	ALPN            badoption.Listable[string] `json:"alpn,omitempty"`
	MinVersion      string                     `json:"min_version,omitempty"`
	MaxVersion      string                     `json:"max_version,omitempty"`
	CipherSuites    badoption.Listable[string] `json:"cipher_suites,omitempty"`
	Certificate     badoption.Listable[string] `json:"certificate,omitempty"`
	CertificatePath string                     `json:"certificate_path,omitempty"`
	Key             badoption.Listable[string] `json:"key,omitempty"`
	KeyPath         string                     `json:"key_path,omitempty"`
	ACME            *InboundACMEOptions        `json:"acme,omitempty"`
	ECH             *InboundECHOptions         `json:"ech,omitempty"`
	Reality         *InboundRealityOptions     `json:"reality,omitempty"`
}

type InboundTLSOptionsContainer struct {
	TLS *InboundTLSOptions `json:"tls,omitempty"`
}

type InboundTLSOptionsWrapper interface {
	TakeInboundTLSOptions() *InboundTLSOptions
	ReplaceInboundTLSOptions(options *InboundTLSOptions)
}

func (o *InboundTLSOptionsContainer) TakeInboundTLSOptions() *InboundTLSOptions {
	return o.TLS
}

func (o *InboundTLSOptionsContainer) ReplaceInboundTLSOptions(options *InboundTLSOptions) {
	o.TLS = options
}

type OutboundTLSOptions struct {
	Enabled               bool                       `json:"enabled,omitempty"`
	DisableSNI            bool                       `json:"disable_sni,omitempty"`
	ServerName            string                     `json:"server_name,omitempty"`
	Insecure              bool                       `json:"insecure,omitempty"`
	ALPN                  badoption.Listable[string] `json:"alpn,omitempty"`
	MinVersion            string                     `json:"min_version,omitempty"`
	MaxVersion            string                     `json:"max_version,omitempty"`
	CipherSuites          badoption.Listable[string] `json:"cipher_suites,omitempty"`
	Certificate           badoption.Listable[string] `json:"certificate,omitempty"`
	CertificatePath       string                     `json:"certificate_path,omitempty"`
	Fragment              bool                       `json:"fragment,omitempty"`
	FragmentFallbackDelay badoption.Duration         `json:"fragment_fallback_delay,omitempty"`
	RecordFragment        bool                       `json:"record_fragment,omitempty"`
	ECH                   *OutboundECHOptions        `json:"ech,omitempty"`
	UTLS                  *OutboundUTLSOptions       `json:"utls,omitempty"`
	Reality               *OutboundRealityOptions    `json:"reality,omitempty"`
}

func NewOutboundTLSOptions(config map[string]any) *OutboundTLSOptions {
	options := OutboundTLSOptions{
		ECH:     &OutboundECHOptions{},
		UTLS:    &OutboundUTLSOptions{},
		Reality: &OutboundRealityOptions{},
	}
	if tls, exists := config["tls"].(bool); exists && tls {
		options.Enabled = true
	}
	if insecure, exists := config["insecure"].(bool); exists {
		options.Enabled = true
		options.Insecure = insecure
	}
	if insecure, exists := config["skip-cert-verify"].(bool); exists {
		options.Enabled = true
		options.Insecure = insecure
	}
	if sni, exists := config["sni"].(string); exists {
		options.ServerName = sni
	}
	if peer, exists := config["peer"].(string); exists {
		options.ServerName = peer
	}
	if servername, exists := config["servername"].(string); exists {
		options.ServerName = servername
	}
	if disableSNI, exists := config["disable-sni"].(bool); exists {
		options.DisableSNI = disableSNI
	}
	if alpn, exists := config["alpn"].([]any); exists {
		var alpnArr []string
		for _, item := range alpn {
			alpnArr = append(alpnArr, fmt.Sprint(item))
		}
		options.ALPN = alpnArr
	}
	if fingerprint, exists := config["client-fingerprint"].(string); exists {
		options.Enabled = true
		options.UTLS.Enabled = true
		options.UTLS.Fingerprint = fingerprint
	}
	if reality, exists := config["reality-opts"].(map[string]any); exists {
		options.Enabled = true
		options.Reality.Enabled = true
		if pbk, exists := reality["public-key"].(string); exists {
			options.Reality.PublicKey = pbk
		}
		if sid, exists := reality["short-id"].(string); exists {
			options.Reality.ShortID = sid
		}
	}
	if ca, exists := config["ca"]; exists {
		options.CertificatePath = fmt.Sprint(ca)
	}
	if caStr, exists := config["ca-str"].([]any); exists {
		var caStrArr []string
		for _, item := range caStr {
			caStrArr = append(caStrArr, fmt.Sprint(item))
		}
		options.Certificate = caStrArr
	}
	if caStr, exists := config["ca_str"].([]any); exists {
		var caStrArr []string
		for _, item := range caStr {
			caStrArr = append(caStrArr, fmt.Sprint(item))
		}
		options.Certificate = caStrArr
	}
	return &options
}

type OutboundTLSOptionsContainer struct {
	TLS *OutboundTLSOptions `json:"tls,omitempty"`
}

type OutboundTLSOptionsWrapper interface {
	TakeOutboundTLSOptions() *OutboundTLSOptions
	ReplaceOutboundTLSOptions(options *OutboundTLSOptions)
}

func (o *OutboundTLSOptionsContainer) TakeOutboundTLSOptions() *OutboundTLSOptions {
	return o.TLS
}

func (o *OutboundTLSOptionsContainer) ReplaceOutboundTLSOptions(options *OutboundTLSOptions) {
	o.TLS = options
}

type InboundRealityOptions struct {
	Enabled           bool                           `json:"enabled,omitempty"`
	Handshake         InboundRealityHandshakeOptions `json:"handshake,omitempty"`
	PrivateKey        string                         `json:"private_key,omitempty"`
	ShortID           badoption.Listable[string]     `json:"short_id,omitempty"`
	MaxTimeDifference badoption.Duration             `json:"max_time_difference,omitempty"`
}

type InboundRealityHandshakeOptions struct {
	ServerOptions
	DialerOptions
}

type InboundECHOptions struct {
	Enabled bool                       `json:"enabled,omitempty"`
	Key     badoption.Listable[string] `json:"key,omitempty"`
	KeyPath string                     `json:"key_path,omitempty"`

	// Deprecated: not supported by stdlib
	PQSignatureSchemesEnabled bool `json:"pq_signature_schemes_enabled,omitempty"`
	// Deprecated: added by fault
	DynamicRecordSizingDisabled bool `json:"dynamic_record_sizing_disabled,omitempty"`
}

type OutboundECHOptions struct {
	Enabled    bool                       `json:"enabled,omitempty"`
	Config     badoption.Listable[string] `json:"config,omitempty"`
	ConfigPath string                     `json:"config_path,omitempty"`

	// Deprecated: not supported by stdlib
	PQSignatureSchemesEnabled bool `json:"pq_signature_schemes_enabled,omitempty"`
	// Deprecated: added by fault
	DynamicRecordSizingDisabled bool `json:"dynamic_record_sizing_disabled,omitempty"`
}

type OutboundUTLSOptions struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type OutboundRealityOptions struct {
	Enabled   bool   `json:"enabled,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}
