package trafficontrol

import (
	"runtime"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashapi/compatible"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/x/list"

	"github.com/gofrs/uuid/v5"
)

type Manager struct {
	uploadTemp          atomic.Int64
	downloadTemp        atomic.Int64
	uploadBlip          atomic.Int64
	downloadBlip        atomic.Int64
	uploadTotal         atomic.Int64
	downloadTotal       atomic.Int64
	directUploadTotal   atomic.Int64
	directDownloadTotal atomic.Int64
	proxyUploadTotal    atomic.Int64
	proxyDownloadTotal  atomic.Int64
	ruleStatistic       compatible.Map[string, *RuleStatistic]

	connections             compatible.Map[uuid.UUID, Tracker]
	closedConnectionsAccess sync.Mutex
	closedConnections       list.List[TrackerMetadata]
	ticker                  *time.Ticker
	done                    chan struct{}
	// process     *process.Process
	memory uint64
}

func NewManager() *Manager {
	manager := &Manager{
		ticker: time.NewTicker(time.Second),
		done:   make(chan struct{}),
		// process: &process.Process{Pid: int32(os.Getpid())},
	}
	go manager.handle()
	return manager
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.Metadata().ID, c)
}

func (m *Manager) Leave(c Tracker) {
	metadata := c.Metadata()
	_, loaded := m.connections.LoadAndDelete(metadata.ID)
	if loaded {
		metadata.ClosedAt = time.Now()
		m.closedConnectionsAccess.Lock()
		defer m.closedConnectionsAccess.Unlock()
		if m.closedConnections.Len() >= 1000 {
			m.closedConnections.PopFront()
		}
		m.closedConnections.PushBack(metadata)
	}
}

func (m *Manager) PushUploaded(size int64, isProxy bool) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
	if isProxy {
		m.proxyUploadTotal.Add(size)
	} else {
		m.directUploadTotal.Add(size)
	}
}

func (m *Manager) PushDownloaded(size int64, isProxy bool) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
	if isProxy {
		m.proxyDownloadTotal.Add(size)
	} else {
		m.directDownloadTotal.Add(size)
	}
}

func (m *Manager) PushRuleUploaded(rule string, size int64) {
	value, ok := m.ruleStatistic.Load(rule)
	if ok {
		value.AddUpload(size)
	} else {
		ruleStat := &RuleStatistic{
			Rule: rule,
		}
		ruleStat.AddUpload(size)
		m.ruleStatistic.Store(rule, ruleStat)
	}
}

func (m *Manager) PushRuleDownloaded(rule string, size int64) {
	value, ok := m.ruleStatistic.Load(rule)
	if ok {
		value.AddDownload(size)
	} else {
		ruleStat := &RuleStatistic{
			Rule: rule,
		}
		ruleStat.AddDownload(size)
		m.ruleStatistic.Store(rule, ruleStat)
	}
}

func (m *Manager) TrafficStatistic() *TrafficStatistic {
	var ruleStatistic []*RuleStatistic
	m.ruleStatistic.Range(func(key string, value *RuleStatistic) bool {
		ruleStatistic = append(ruleStatistic, value)
		return true
	})
	return &TrafficStatistic{
		RuleStatistic: ruleStatistic,
	}
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up int64, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) ConnectionsLen() int {
	return m.connections.Len()
}

func (m *Manager) Connections() []TrackerMetadata {
	var connections []TrackerMetadata
	m.connections.Range(func(_ uuid.UUID, value Tracker) bool {
		connections = append(connections, value.Metadata())
		return true
	})
	return connections
}

func (m *Manager) ClosedConnections() []TrackerMetadata {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	return m.closedConnections.Array()
}

func (m *Manager) Connection(id uuid.UUID) Tracker {
	connection, loaded := m.connections.Load(id)
	if !loaded {
		return nil
	}
	return connection
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []Tracker
	m.connections.Range(func(_ uuid.UUID, value Tracker) bool {
		if value.Metadata().OutboundType != C.TypeDNS {
			connections = append(connections, value)
		}
		return true
	})

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.memory = memStats.StackInuse + memStats.HeapInuse + memStats.HeapIdle - memStats.HeapReleased

	return &Snapshot{
		Upload:              m.uploadTotal.Load(),
		Download:            m.downloadTotal.Load(),
		Connections:         connections,
		Memory:              m.memory,
		DirectUploadTotal:   m.directUploadTotal.Load(),
		DirectDownloadTotal: m.directDownloadTotal.Load(),
		ProxyUploadTotal:    m.proxyUploadTotal.Load(),
		ProxyDownloadTotal:  m.proxyDownloadTotal.Load(),
	}
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.directUploadTotal.Store(0)
	m.proxyUploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
	m.directDownloadTotal.Store(0)
	m.proxyDownloadTotal.Store(0)
	m.ruleStatistic.Clear()
}

func (m *Manager) handle() {
	var uploadTemp int64
	var downloadTemp int64
	for {
		select {
		case <-m.done:
			return
		case <-m.ticker.C:
		}
		uploadTemp = m.uploadTemp.Swap(0)
		downloadTemp = m.downloadTemp.Swap(0)
		m.uploadBlip.Store(uploadTemp)
		m.downloadBlip.Store(downloadTemp)
	}
}

func (m *Manager) Close() error {
	m.ticker.Stop()
	close(m.done)
	return nil
}

type Snapshot struct {
	Download            int64
	Upload              int64
	Connections         []Tracker
	Memory              uint64
	DirectUploadTotal   int64
	DirectDownloadTotal int64
	ProxyUploadTotal    int64
	ProxyDownloadTotal  int64
}

type TrafficStatistic struct {
	RuleStatistic []*RuleStatistic `json:"ruleStatistic"`
}

func (s *Snapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"downloadTotal":       s.Download,
		"uploadTotal":         s.Upload,
		"directUploadTotal":   s.DirectUploadTotal,
		"directDownloadTotal": s.DirectDownloadTotal,
		"proxyUploadTotal":    s.ProxyUploadTotal,
		"proxyDownloadTotal":  s.ProxyDownloadTotal,
		"connections":         common.Map(s.Connections, func(t Tracker) TrackerMetadata { return t.Metadata() }),
		"memory":              s.Memory,
	})
}
