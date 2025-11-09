package local

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderLocalOptions](registry, C.ProviderTypeLocal, NewProviderLocal)
}

var _ adapter.Provider = (*ProviderLocal)(nil)

type ProviderLocal struct {
	provider.Adapter
	ctx           context.Context
	logger        log.ContextLogger
	provider      adapter.ProviderManager
	lastOutbounds []option.Outbound
	watcher       *fswatch.Watcher
}

func NewProviderLocal(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderLocalOptions) (adapter.Provider, error) {
	if options.Path == "" {
		return nil, E.New("provider path is required")
	}
	var (
		outbound = service.FromContext[adapter.OutboundManager](ctx)
		logger   = logFactory.NewLogger(F.ToString("provider/local", "[", tag, "]"))
	)
	local := &ProviderLocal{
		Adapter: provider.NewAdapter(ctx, router, outbound, logFactory, logger,
			tag, C.ProviderTypeLocal, options.Path, options.Icon,
			options.FilterOptions, options.HealthCheck, options.Override),
		ctx:      ctx,
		logger:   logger,
		provider: service.FromContext[adapter.ProviderManager](ctx),
	}
	filePath := filemanager.BasePath(ctx, options.Path)
	filePath, _ = filepath.Abs(filePath)
	err := local.reloadFile(filePath)
	if err != nil {
		return nil, err
	}
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{filePath},
		Callback: func(path string) {
			uErr := local.reloadFile(path)
			if uErr != nil {
				logger.Error(E.Cause(uErr, "reload provider ", tag))
			}
			local.UpdateGroups()
		},
	})
	if err != nil {
		return nil, err
	}
	local.watcher = watcher
	return local, nil
}

func (p *ProviderLocal) Start() error {
	if p.watcher != nil {
		err := p.watcher.Start()
		if err != nil {
			p.logger.Error(E.Cause(err, "watch provider file"))
		}
	}
	return nil
}

func (p *ProviderLocal) PostStart() error {
	return p.Adapter.PostStart()
}

func (p *ProviderLocal) UpdateProvider() error {
	return nil
}

func (p *ProviderLocal) Wait() {}

func (p *ProviderLocal) reloadFile(path string) error {
	if fileInfo, err := os.Stat(path); err == nil {
		p.SetUpdatedTime(fileInfo.ModTime())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	outbounds, err := p.UpdateProviderFromContent(p.ctx, string(content), p.lastOutbounds)
	if err != nil {
		return err
	}
	p.lastOutbounds = outbounds
	return nil
}

func (p *ProviderLocal) Close() error {
	return common.Close(&p.Adapter, common.PtrOrNil(p.watcher))
}
