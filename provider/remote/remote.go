package remote

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/betterdecode"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var _ adapter.Provider = (*ProviderRemote)(nil)

type ProviderRemote struct {
	provider.Adapter
	ctx      context.Context
	cancel   context.CancelFunc
	logger   log.ContextLogger
	outbound adapter.OutboundManager
	provider adapter.ProviderManager
	dialer   N.Dialer

	subscriptionInfo *adapter.SubscriptionInfo

	// update
	lastEtag      string
	updating      atomic.Bool
	ticker        *time.Ticker
	update        chan struct{}
	lastUpdated   time.Time
	lastOutbounds []option.Outbound

	// download
	url            string
	userAgent      string
	downloadDetour string
	updateInterval time.Duration
}

func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	var path string
	if options.Path != "" {
		path = filemanager.BasePath(ctx, options.Path)
		path, _ = filepath.Abs(path)
	}
	if rw.IsDir(path) {
		return nil, E.New("provider path is a directory: ", path)
	}
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Hour {
		updateInterval = time.Hour
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	updateChan := make(chan struct{})
	close(updateChan)
	return &ProviderRemote{
		Adapter: provider.NewAdapter(ctx, router, outbound, logFactory, logger,
			tag, C.ProviderTypeRemote, options.Path, options.Icon,
			options.FilterOptions, options.HealthCheck, options.Override),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		outbound: outbound,
		provider: service.FromContext[adapter.ProviderManager](ctx),
		update:   updateChan,

		url:            options.URL,
		userAgent:      userAgent,
		downloadDetour: options.DownloadDetour,
		updateInterval: updateInterval,
	}, nil
}

func (p *ProviderRemote) Start() error {
	err := p.loadCacheFile()
	if err != nil {
		return E.Cause(err, "restore cached outbound provider")
	}
	var dialer N.Dialer
	if p.downloadDetour != "" {
		outbound, loaded := p.outbound.Outbound(p.downloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", p.downloadDetour)
		}
		dialer = outbound
	} else {
		dialer = p.outbound.Default()
	}
	p.dialer = dialer
	return nil
}

func (p *ProviderRemote) PostStart() error {
	if err := p.Adapter.PostStart(); err != nil {
		return err
	}
	// no provider cached
	if p.UpdatedTime().IsZero() {
		p.updateOnce()
	}
	go p.loopUpdate()
	return nil
}

func (p *ProviderRemote) UpdateProvider() error {
	if p.ticker != nil {
		p.ticker.Reset(p.updateInterval)
	}
	return p.fetch(p.ctx)
}

func (p *ProviderRemote) SubscriptionInfo() *adapter.SubscriptionInfo {
	return p.subscriptionInfo
}

func (p *ProviderRemote) Wait() {
	if p.updating.Load() {
		<-p.update
	}
}

func (p *ProviderRemote) Close() error {
	p.cancel()
	if p.ticker != nil {
		p.ticker.Stop()
	}
	return common.Close(&p.Adapter)
}

func (p *ProviderRemote) updateOnce() {
	if err := p.fetch(p.ctx); err != nil {
		p.logger.Error("update outbound provider: ", err)
	}
}

func (p *ProviderRemote) fetch(ctx context.Context) error {
	defer runtime.GC()
	if p.updating.Swap(true) {
		return E.New("provider is updating")
	}
	p.update = make(chan struct{})
	defer func() {
		close(p.update)
		p.updating.Store(false)
	}()
	p.logger.Debug("updating outbound provider ", p.Tag(), " from URL: ", p.url)
	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, p.url, nil)
	if err != nil {
		return err
	}
	if p.lastEtag != "" {
		req.Header.Set("If-None-Match", p.lastEtag)
	}
	req.Header.Set("User-Agent", p.userAgent)
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	subscriptionInfoStr := resp.Header.Get("subscription-userinfo")
	subscriptionInfo := parseSubscriptionInfo(subscriptionInfoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		p.subscriptionInfo = subscriptionInfo
		p.SetUpdatedTime(time.Now())
		if p.Path() != "" {
			content, _ := os.ReadFile(p.Path())
			p.saveCacheFile(subscriptionInfo, content)
		}
		p.logger.Info("update outbound provider ", p.Tag(), ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", resp.Status)
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	contentRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	eTagHeader := resp.Header.Get("Etag")
	if eTagHeader != "" {
		p.lastEtag = eTagHeader
	}
	content := betterdecode.DecodeBase64Safe(string(contentRaw))
	if subscriptionInfo == nil {
		firstLine, others := getFirstLine(content)
		if subscriptionInfo = parseSubscriptionInfo(firstLine); subscriptionInfo != nil {
			subscriptionInfoStr = firstLine
			content = betterdecode.DecodeBase64Safe(others)
		}
	}
	if err := p.updateProviderFromContent(content); err != nil {
		return err
	}
	p.UpdateGroups()
	p.subscriptionInfo = subscriptionInfo
	p.SetUpdatedTime(time.Now())
	if p.Path() != "" {
		p.saveCacheFile(subscriptionInfo, []byte(content))
	}
	p.logger.Info("updated outbound provider ", p.Tag())
	return nil
}

func (p *ProviderRemote) loadCacheFile() error {
	if p.Path() == "" {
		return nil
	}
	if !rw.IsFile(p.Path()) {
		return nil
	}
	file, _ := os.Open(p.Path())
	content, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	var lastEtag string
	fs, _ := file.Stat()
	err = p.loadFromContent(content)
	if err != nil {
		return err
	}
	p.SetUpdatedTime(fs.ModTime())
	p.lastEtag = lastEtag
	return nil
}

func (p *ProviderRemote) loadFromContent(contentRaw []byte) error {
	content := betterdecode.DecodeBase64Safe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	if subscriptionInfo := parseSubscriptionInfo(firstLine); subscriptionInfo != nil {
		p.subscriptionInfo = subscriptionInfo
		content = betterdecode.DecodeURIComponent(others)
	}
	if err := p.updateProviderFromContent(content); err != nil {
		return err
	}
	return nil
}

func (p *ProviderRemote) loopUpdate() {
	if time.Since(p.UpdatedTime()) < p.updateInterval {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(time.Until(p.UpdatedTime().Add(p.updateInterval))):
			p.updateOnce()
		}
	} else {
		p.updateOnce()
	}
	p.ticker = time.NewTicker(p.updateInterval)
	for {
		runtime.GC()
		select {
		case <-p.ctx.Done():
			return
		case <-p.ticker.C:
			p.updateOnce()
		}
	}
}

func (p *ProviderRemote) saveCacheFile(info *adapter.SubscriptionInfo, contentRaw []byte) {
	content := contentRaw
	if info != nil {
		infoStr := fmt.Sprint(
			"# upload=", info.Upload,
			"; download=", info.Download,
			"; total=", info.Total,
			"; expire=", info.Expire,
			";")
		content = append([]byte(infoStr+"\n"), content...)
	}
	dir := filepath.Dir(p.Path())
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := filemanager.MkdirAll(p.ctx, dir, 0o755)
		if err != nil {
			p.logger.Error("create directory for provider cache file: ", E.Cause(err, dir))
			return
		}
	}
	if err := filemanager.WriteFile(p.ctx, p.Path(), content, 0o666); err != nil {
		p.logger.Error("write provider cache file: ", E.Cause(err, p.Path()))
	}
}

func (p *ProviderRemote) updateProviderFromContent(content string) error {
	outbounds, err := p.UpdateProviderFromContent(p.ctx, content, p.lastOutbounds)
	if err != nil {
		return err
	}
	p.lastOutbounds = outbounds
	return nil
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}

func parseSubscriptionInfo(subscriptionInfoStr string) *adapter.SubscriptionInfo {
	info := adapter.SubscriptionInfo{}
	if subscriptionInfoStr == "" {
		return nil
	}
	reg := regexp.MustCompile(`(upload|download|total|expire)[\s\t]*=[\s\t]*(-?\d*);?`)
	matches := reg.FindAllStringSubmatch(subscriptionInfoStr, 4)
	if len(matches) == 0 {
		return nil
	}
	for _, match := range matches {
		key, value := match[1], match[2]
		i, _ := strconv.ParseInt(value, 10, 64)
		switch key {
		case "upload":
			info.Upload = i
		case "download":
			info.Download = i
		case "total":
			info.Total = i
		case "expire":
			info.Expire = i
		default:
			return nil
		}
	}
	return &info
}
