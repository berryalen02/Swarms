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

type MUDPProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (udp *MUDPProbe) Init(ctx context.Context, logger *log.Logger) error {
	udp.Module.Init(ctx, logger)
	udp.Module.SetChild(udp)
	udp.eventMaps = make([]*ebpf.Map, 0, 2)
	udp.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (udp *MUDPProbe) Start() error {
	if err := udp.start(); err != nil {
		return err
	}
	return nil
}

func (udp *MUDPProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/udp_lookup_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	udp.setupManagers()

	// initialize the bootstrap manager
	if err := udp.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), udp.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := udp.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = udp.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (udp *MUDPProbe) Close() error {
	if err := udp.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (udp *MUDPProbe) setupManagers() {
	udp.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kprobe/udp_recvmsg",
				EbpfFuncName:     "trace_udp_recvmsg",
				AttachToFuncName: "udp_recvmsg",
			},
			{
				Section:          "kretprobe/udp_recvmsg",
				EbpfFuncName:     "trace_ret_udp_recvmsg",
				AttachToFuncName: "udp_recvmsg",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "dns_events",
			},
		},
	}

	udp.bpfManagerOptions = manager.Options{
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

func (udp *MUDPProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := udp.eventFuncMaps[em]
	return fun, found
}

func (udp *MUDPProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	DNSEventsMap, found, err := udp.bpfManager.GetMap("dns_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	udp.eventMaps = append(udp.eventMaps, DNSEventsMap)
	udp.eventFuncMaps[DNSEventsMap] = &UDPEvent{}

	return nil
}

func (udp *MUDPProbe) Events() []*ebpf.Map {
	return udp.eventMaps
}

func init() {
	mod := &MUDPProbe{}
	mod.name = "EBPFProbeKUDP"
	mod.mType = PROBE_TYPE_KPROBE
	//Register(mod)
}
