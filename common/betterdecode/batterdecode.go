package betterdecode

import (
	"encoding/base64"
	"net/url"
	"strconv"
)

func DecodeURIComponent(s string) string {
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	return s
}

func DecodeBase64Safe(s string) string {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(decoded)
	}
	return s
}

func stringToUint16(s string) uint16 {
	if val, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(val)
	}
	return 0
}
