package group

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup             = (*Selector)(nil)
	_ adapter.ConnectionHandlerEx       = (*Selector)(nil)
	_ adapter.PacketConnectionHandlerEx = (*Selector)(nil)
)

type Selector struct {
	*Adapter
	defaultTag string
	selected   common.TypedValue[adapter.Outbound]
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	providerGroup, err := NewAdapter(
		C.TypeSelector,
		tag,
		options.Icon,
		[]string{N.NetworkTCP, N.NetworkUDP},
		options.Outbounds,
		ctx,
		logger,
		options.Providers,
		options.Includes,
		options.Excludes,
		options.UseAllProviders,
		options.InterruptExistConnections,
	)
	if err != nil {
		return nil, err
	}

	selector := &Selector{
		Adapter:    providerGroup,
		defaultTag: options.Default,
	}

	return selector, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start() error {
	err := s.InitializeProviders(s.onProviderUpdated)
	if err != nil {
		return err
	}

	tags, outboundByTag, _, err := s.FilterOutbounds("")
	if err != nil {
		return err
	}

	s.SetTags(tags)
	s.SetOutbounds(outboundByTag)

	selected, err := s.outboundSelect()
	if err != nil {
		return err
	}
	s.selected.Store(selected)
	return nil
}

func (s *Selector) Selected() adapter.Outbound {
	selected := s.selected.Load()
	if selected == nil {
		return s.outbounds[s.GetTags()[0]]
	}
	return selected

}

func (s *Selector) Now() string {
	selected := s.Selected()
	for selected != nil {
		if group, isGroup := selected.(adapter.OutboundGroup); isGroup {
			selected = group.Selected()
		} else {
			return selected.Tag()
		}
	}
	return s.GetTags()[0]
}

func (s *Selector) All() []string {
	return s.GetTags()
}

func (s *Selector) SelectOutbound(tag string) bool {
	detour, loaded := s.GetOutbounds()[tag]
	if !loaded {
		return false
	}
	if s.selected.Swap(detour) == detour {
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.GetContext())
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.GetLogger().Error("store selected: ", err)
			}
		}
	}
	s.InterruptConnections()
	return true
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.selected.Load().DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.GetInterruptGroup().NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := s.selected.Load().ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.GetInterruptGroup().NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	if outboundHandler, isHandler := selected.(adapter.ConnectionHandlerEx); isHandler {
		outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
	} else {
		s.GetConnectionManager().NewConnection(ctx, selected, conn, metadata, onClose)
	}
}

func (s *Selector) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	if outboundHandler, isHandler := selected.(adapter.PacketConnectionHandlerEx); isHandler {
		outboundHandler.NewPacketConnectionEx(ctx, conn, metadata, onClose)
	} else {
		s.GetConnectionManager().NewPacketConnection(ctx, selected, conn, metadata, onClose)
	}
}

func (s *Selector) onProviderUpdated(tag string) error {
	_, loaded := s.GetProviders()[tag]
	if !loaded {
		return E.New(s.Tag(), ": ", "outbound provider not found: ", tag)
	}

	tags, outboundByTag, _, _ := s.FilterOutbounds(tag)
	s.SetTags(tags)
	s.SetOutbounds(outboundByTag)

	if !s.SetUpdating(true) {
		go func() {
			for _, provider := range s.provider.Providers() {
				provider.Wait()
			}
			detour, _ := s.outboundSelect()
			if s.selected.Swap(detour) != detour {
				s.InterruptConnections()
			}
			s.SetUpdating(false)
		}()
	}
	return nil
}

func (s *Selector) outboundSelect() (adapter.Outbound, error) {
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.GetContext())
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour, loaded := s.GetOutbounds()[selected]
				if loaded {
					return detour, nil
				}
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := s.GetOutbounds()[s.defaultTag]
		if !loaded {
			return nil, E.New("default outbound not found: ", s.defaultTag)
		}
		return detour, nil
	}

	return s.GetOutbounds()[s.GetTags()[0]], nil
}
