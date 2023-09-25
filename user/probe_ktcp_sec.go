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

type MTCPSecProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (TCPSec *MTCPSecProbe) Init(ctx context.Context, logger *log.Logger) error {
	TCPSec.Module.Init(ctx, logger)
	TCPSec.Module.SetChild(TCPSec)
	TCPSec.eventMaps = make([]*ebpf.Map, 0, 2)
	TCPSec.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (TCPSec *MTCPSecProbe) Start() error {
	if err := TCPSec.start(); err != nil {
		return err
	}
	return nil
}

func (TCPSec *MTCPSecProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/sec_socket_connect_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	TCPSec.setupManagers()

	// initialize the bootstrap manager
	if err := TCPSec.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), TCPSec.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := TCPSec.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = TCPSec.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (TCPSec *MTCPSecProbe) Close() error {
	if err := TCPSec.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (TCPSec *MTCPSecProbe) setupManagers() {
	TCPSec.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kprobe/security_socket_connect",
				EbpfFuncName:     "kprobe__security_socket_connect",
				AttachToFuncName: "security_socket_connect",
			},
		},
		//Ipv4Events  *ebpf.Map `ebpf:"ipv4_events"`
		//Ipv6Events  *ebpf.Map `ebpf:"ipv6_events"`
		//OtherEvents *ebpf.Map `ebpf:"other_socket_events"`
		Maps: []*manager.Map{
			{
				Name: "ipv4_events",
			},
			{
				Name: "ipv6_events",
			},
			{
				Name: "other_socket_events",
			},
		},
	}

	TCPSec.bpfManagerOptions = manager.Options{
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

func (TCPSec *MTCPSecProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := TCPSec.eventFuncMaps[em]
	return fun, found
}

func (TCPSec *MTCPSecProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	IPv4EventsMap, found, err := TCPSec.bpfManager.GetMap("ipv4_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	TCPSec.eventMaps = append(TCPSec.eventMaps, IPv4EventsMap)
	TCPSec.eventFuncMaps[IPv4EventsMap] = &EventIPV4{}

	IPv6EventsMap, found, err := TCPSec.bpfManager.GetMap("ipv6_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	TCPSec.eventMaps = append(TCPSec.eventMaps, IPv6EventsMap)
	TCPSec.eventFuncMaps[IPv6EventsMap] = &EventIPV6{}

	otherEventsMap, found, err := TCPSec.bpfManager.GetMap("other_socket_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	TCPSec.eventMaps = append(TCPSec.eventMaps, otherEventsMap)
	TCPSec.eventFuncMaps[otherEventsMap] = &EventOther{}
	return nil
}

func (TCPSec *MTCPSecProbe) Events() []*ebpf.Map {
	return TCPSec.eventMaps
}

func init() {
	mod := &MTCPSecProbe{}
	mod.name = "EBPFProbeKTCPSec"
	mod.mType = PROBE_TYPE_KPROBE
	Register(mod)
}
