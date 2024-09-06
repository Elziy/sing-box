package trafficontrol

import (
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/json"
)

type RuleStatistic struct {
	Rule          string
	UploadTotal   atomic.Int64
	DownloadTotal atomic.Int64
}

func (rs *RuleStatistic) AddDownload(size int64) {
	rs.DownloadTotal.Add(size)
}

func (rs *RuleStatistic) AddUpload(size int64) {
	rs.UploadTotal.Add(size)
}

func (rs *RuleStatistic) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"rule":     rs.Rule,
		"upload":   rs.UploadTotal.Load(),
		"download": rs.DownloadTotal.Load(),
	})
}
