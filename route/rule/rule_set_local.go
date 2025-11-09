package rule

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/filemanager"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	ctx         context.Context
	logger      logger.Logger
	tag         string
	access      sync.RWMutex
	rules       []adapter.HeadlessRule
	ruleCount   uint32
	metadata    adapter.RuleSetMetadata
	filePath    string
	fileFormat  string
	lastUpdated time.Time
	watcher     *fswatch.Watcher
	callbacks   list.List[adapter.RuleSetUpdateCallback]
	refs        atomic.Int32
}

func NewLocalRuleSet(ctx context.Context, logger logger.Logger, options option.RuleSet) (*LocalRuleSet, error) {
	ruleSet := &LocalRuleSet{
		ctx:        ctx,
		logger:     logger,
		tag:        options.Tag,
		filePath:   filemanager.BasePath(ctx, options.Path),
		fileFormat: options.Format,
	}
	if options.Type == C.RuleSetTypeInline {
		if len(options.InlineOptions.Rules) == 0 {
			return nil, E.New("empty inline rule-set")
		}
		err := ruleSet.reloadRules(options.InlineOptions.Rules)
		if err != nil {
			return nil, err
		}
	} else {
		ruleSet.filePath, _ = filepath.Abs(ruleSet.filePath)
		err := ruleSet.reloadFile(ruleSet.filePath)
		if err != nil {
			return nil, err
		}
		watcher, err := fswatch.NewWatcher(fswatch.Options{
			Path: []string{ruleSet.filePath},
			Callback: func(path string) {
				uErr := ruleSet.reloadFile(path)
				if uErr != nil {
					logger.Error(E.Cause(uErr, "reload rule-set ", options.Tag))
				}
			},
		})
		if err != nil {
			return nil, err
		}
		ruleSet.watcher = watcher
	}
	return ruleSet, nil
}

func (s *LocalRuleSet) Name() string {
	return s.tag
}

func (s *LocalRuleSet) Type() string {
	return C.RuleSetTypeLocal
}

func (s *LocalRuleSet) Format() string {
	return s.fileFormat
}

func (s *LocalRuleSet) Path() string {
	return s.filePath
}

func (s *LocalRuleSet) RuleCount() uint32 {
	return s.ruleCount
}

func (s *LocalRuleSet) UpdatedTime() time.Time {
	return s.lastUpdated
}

func (s *LocalRuleSet) Update(context.Context) error {
	err := s.reloadFile(s.filePath)
	if err != nil {
		s.logger.Error(E.Cause(err, "reload rule-set ", s.tag))
	}
	return nil
}

func (s *LocalRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	if s.watcher != nil {
		err := s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch rule-set file"))
		}
	}
	return nil
}

func (s *LocalRuleSet) reloadFile(path string) error {
	var ruleSet option.PlainRuleSetCompat
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	fs, _ := file.Stat()
	s.lastUpdated = fs.ModTime()
	switch s.fileFormat {
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
		return E.New("unknown rule-set format: ", s.fileFormat)
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules)
}

func (s *LocalRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
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
	var metadata adapter.RuleSetMetadata
	metadata.ContainsProcessRule = hasHeadlessRule(headlessRules, isProcessHeadlessRule)
	metadata.ContainsWIFIRule = hasHeadlessRule(headlessRules, isWIFIHeadlessRule)
	metadata.ContainsIPCIDRRule = hasHeadlessRule(headlessRules, isIPCIDRHeadlessRule)
	s.access.Lock()
	s.rules = rules
	s.ruleCount = ruleCount
	s.metadata = metadata
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *LocalRuleSet) PostStart() error {
	return nil
}

func (s *LocalRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *LocalRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *LocalRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *LocalRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *LocalRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *LocalRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *LocalRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *LocalRuleSet) Close() error {
	s.rules = nil
	return common.Close(common.PtrOrNil(s.watcher))
}

func (s *LocalRuleSet) Match(metadata *adapter.InboundContext) bool {
	for _, rule := range s.rules {
		if rule.Match(metadata) {
			return true
		}
	}
	return false
}
