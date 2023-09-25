package user

import (
	"bytes"
	"context"
	"log"
	"math"
	"swarms/assets"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type MTCPProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (TCP *MTCPProbe) Init(ctx context.Context, logger *log.Logger) error {
	TCP.Module.Init(ctx, logger)
	TCP.Module.SetChild(TCP)
	TCP.eventMaps = make([]*ebpf.Map, 0, 2)
	TCP.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (TCP *MTCPProbe) Start() error {
	if err := TCP.start(); err != nil {
		return err
	}
	return nil
}

func (TCP *MTCPProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/tcp_set_state_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	TCP.setupManagers()

	// initialize the bootstrap manager
	if err := TCP.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), TCP.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := TCP.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = TCP.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (TCP *MTCPProbe) Close() error {
	if err := TCP.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (TCP *MTCPProbe) setupManagers() {
	TCP.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kprobe/tcp_set_state",
				EbpfFuncName:     "kprobe__tcp_set_state",
				AttachToFuncName: "tcp_set_state",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
			},
			{
				Name: "conns",
			},
		},
	}

	TCP.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (TCP *MTCPProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := TCP.eventFuncMaps[em]
	return fun, found
}

func (TCP *MTCPProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	TCP.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	//TCPEvents *ebpf.Map `ebpf:"events"`
	TCPEventsMap, found, err := TCP.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	TCP.eventMaps = append(TCP.eventMaps, TCPEventsMap)
	TCP.eventFuncMaps[TCPEventsMap] = &TCPEvent{}
	return nil
}

func (TCP *MTCPProbe) Events() []*ebpf.Map {
	return TCP.eventMaps
}

func init() {
	mod := &MTCPProbe{}
	mod.name = "EBPFProbeKTCP"
	mod.mType = PROBE_TYPE_KPROBE
	Register(mod)
}
