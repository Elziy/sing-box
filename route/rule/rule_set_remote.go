package rule

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	outbound       adapter.OutboundManager
	options        option.RuleSet
	updateInterval time.Duration
	dialer         N.Dialer
	access         sync.RWMutex
	rules          []adapter.HeadlessRule
	ruleCount      uint32
	metadata       adapter.RuleSetMetadata
	lastUpdated    time.Time
	lastEtag       string
	updateTicker   *time.Ticker
	pauseManager   pause.Manager
	callbacks      list.List[adapter.RuleSetUpdateCallback]
	refs           atomic.Int32
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, options option.RuleSet) *RemoteRuleSet {
	ctx, cancel := context.WithCancel(ctx)
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	return &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		options:        options,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}
}

func (s *RemoteRuleSet) Name() string {
	return s.options.Tag
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *RemoteRuleSet) Type() string {
	return C.RuleSetTypeRemote
}

func (s *RemoteRuleSet) Format() string {
	return s.options.Format
}

func (s *RemoteRuleSet) Path() string {
	basePath := filemanager.BasePath(s.ctx, s.options.Path)
	path, err := filepath.Abs(basePath)
	if err != nil {
		return path
	}
	return basePath
}

func (s *RemoteRuleSet) RuleCount() uint32 {
	return s.ruleCount
}

func (s *RemoteRuleSet) UpdatedTime() time.Time {
	return s.lastUpdated
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	//s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	var dialer N.Dialer
	if s.options.RemoteOptions.DownloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.options.RemoteOptions.DownloadDetour)
		if !loaded {
			return E.New("download detour not found: ", s.options.RemoteOptions.DownloadDetour)
		}
		dialer = outbound
	} else {
		dialer = s.outbound.Default()
	}
	s.dialer = dialer
	if rw.IsDir(s.Path()) {
		return E.New("rule_set path is a directory: ", s.Path())
	}

	_ = s.reloadFile()

	if s.lastUpdated.IsZero() {
		err := s.fetch(ctx, startContext)
		if err != nil {
			return E.Cause(err, "initial rule-set: ", s.options.Tag)
		}
	}
	s.updateTicker = time.NewTicker(s.updateInterval)
	return nil
}

func (s *RemoteRuleSet) reloadFile() error {
	var ruleSet option.PlainRuleSetCompat
	file, err := os.Open(s.Path())
	if err != nil {
		return err
	}
	fs, _ := file.Stat()
	s.lastUpdated = fs.ModTime()
	switch s.options.Format {
	case C.RuleSetFormatSource, "":
		content, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}

	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(file, false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.options.Format)
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules)
}

func (s *RemoteRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	var ruleCount uint32 = 0
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		ruleCount += rules[i].RuleCount()
	}
	s.access.Lock()
	s.metadata.ContainsProcessRule = hasHeadlessRule(headlessRules, isProcessHeadlessRule)
	s.metadata.ContainsWIFIRule = hasHeadlessRule(headlessRules, isWIFIHeadlessRule)
	s.metadata.ContainsIPCIDRRule = hasHeadlessRule(headlessRules, isIPCIDRHeadlessRule)
	s.rules = rules
	s.ruleCount = ruleCount
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *RemoteRuleSet) PostStart() error {
	go s.loopUpdate()
	return nil
}

func (s *RemoteRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *RemoteRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *RemoteRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *RemoteRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *RemoteRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) loadBytes(content []byte) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.options.Format {
	case C.RuleSetFormatSource:
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(bytes.NewReader(content), false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.options.Format)
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules)
}

func (s *RemoteRuleSet) loopUpdate() {
	if time.Since(s.lastUpdated) > s.updateInterval {
		err := s.fetch(s.ctx, nil)
		if err != nil {
			s.logger.Error("fetch rule-set ", s.options.Tag, ": ", err)
		} else if s.refs.Load() == 0 {
			s.rules = nil
		}
	}
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.updateTicker.C:
			s.updateOnce()
		}
	}
}

func (s *RemoteRuleSet) updateOnce() {
	err := s.fetch(s.ctx, nil)
	if err != nil {
		s.logger.Error("fetch rule-set ", s.options.Tag, ": ", err)
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) Update(ctx context.Context) error {
	err := s.fetch(log.ContextWithNewID(ctx), nil)
	if err != nil {
		return err
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
	return nil
}

func (s *RemoteRuleSet) fetch(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.logger.Debug("updating rule-set ", s.options.Tag, " from URL: ", s.options.RemoteOptions.URL)
	var httpClient *http.Client
	if startContext != nil {
		httpClient = startContext.HTTPClient(s.options.RemoteOptions.DownloadDetour, s.dialer)
	} else {
		httpClient = &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: C.TCPTimeout,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
				},
				TLSClientConfig: &tls.Config{
					Time:    ntp.TimeFuncFromContext(s.ctx),
					RootCAs: adapter.RootPoolFromContext(s.ctx),
				},
			},
		}
	}
	request, err := http.NewRequest("GET", s.options.RemoteOptions.URL, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	response, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.lastUpdated = time.Now()
		// 更新 修改时间戳
		_ = os.Chtimes(s.Path(), s.lastUpdated, s.lastUpdated)
		s.logger.Info("updating rule-set ", s.options.Tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		_ = response.Body.Close()
		return err
	}
	err = s.loadBytes(content)
	if err != nil {
		_ = response.Body.Close()
		return err
	}
	_ = response.Body.Close()
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = time.Now()
	if s.Path() == "" {
		return nil
	}
	dir := filepath.Dir(s.Path())
	if _, err := os.ReadDir(dir); err != nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.logger.ErrorContext(ctx, "make rule-set path error ", err)
		} else {
			s.logger.InfoContext(ctx, "make rule-set path ", dir)
		}
	}
	err = os.WriteFile(s.Path(), content, 0o755)
	if err != nil {
		s.logger.ErrorContext(ctx, "write rule-set ", s.Name(), " error: ", err)
	}
	s.logger.Info("updated rule-set ", s.options.Tag)
	return nil
}

func (s *RemoteRuleSet) Close() error {
	s.rules = nil
	s.cancel()
	if s.updateTicker != nil {
		s.updateTicker.Stop()
	}
	return nil
}

func (s *RemoteRuleSet) Match(metadata *adapter.InboundContext) bool {
	for _, rule := range s.rules {
		if rule.Match(metadata) {
			return true
		}
	}
	return false
}
