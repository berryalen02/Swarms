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

type MUDNSProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (udns *MUDNSProbe) Init(ctx context.Context, logger *log.Logger) error {
	udns.Module.Init(ctx, logger)
	udns.Module.SetChild(udns)
	udns.eventMaps = make([]*ebpf.Map, 0, 2)
	udns.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (udns *MUDNSProbe) Start() error {
	if err := udns.start(); err != nil {
		return err
	}
	return nil
}

func (udns *MUDNSProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/dns_lookup_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	udns.setupManagers()

	// initialize the bootstrap manager
	if err := udns.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), udns.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := udns.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = udns.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (udns *MUDNSProbe) Close() error {
	if err := udns.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (udns *MUDNSProbe) setupManagers() {
	udns.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/getaddrinfo",
				EbpfFuncName:     "getaddrinfo_entry",
				AttachToFuncName: "getaddrinfo",
				BinaryPath:       "/lib/x86_64-linux-gnu/libc.so.6",
			},
			{
				Section:          "uretprobe/getaddrinfo",
				EbpfFuncName:     "getaddrinfo_return",
				AttachToFuncName: "getaddrinfo",
				BinaryPath:       "/lib/x86_64-linux-gnu/libc.so.6",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	udns.bpfManagerOptions = manager.Options{
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

func (udns *MUDNSProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := udns.eventFuncMaps[em]
	return fun, found
}

func (udns *MUDNSProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	DNSEventsMap, found, err := udns.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	udns.eventMaps = append(udns.eventMaps, DNSEventsMap)
	udns.eventFuncMaps[DNSEventsMap] = &DNSEVENT{}

	return nil
}

func (udns *MUDNSProbe) Events() []*ebpf.Map {
	return udns.eventMaps
}

func init() {
	mod := &MUDNSProbe{}
	mod.name = "EBPFProbeUDNS"
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
