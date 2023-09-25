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

type MProcProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (proc *MProcProbe) Init(ctx context.Context, logger *log.Logger) error {
	proc.Module.Init(ctx, logger)
	proc.Module.SetChild(proc)
	proc.eventMaps = make([]*ebpf.Map, 0, 2)
	proc.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (proc *MProcProbe) Start() error {
	if err := proc.start(); err != nil {
		return err
	}
	return nil
}

func (proc *MProcProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/proc_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	proc.setupManagers()

	// initialize the bootstrap manager
	if err := proc.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), proc.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := proc.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = proc.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (proc *MProcProbe) Close() error {
	if err := proc.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (proc *MProcProbe) setupManagers() {
	proc.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kretprobe/copy_process",
				EbpfFuncName:     "kretprobe_copy_process",
				AttachToFuncName: "copy_process",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "ringbuf_proc",
			},
		},
	}

	proc.bpfManagerOptions = manager.Options{
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

func (proc *MProcProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := proc.eventFuncMaps[em]
	return fun, found
}

func (proc *MProcProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	procEventsMap, found, err := proc.bpfManager.GetMap("ringbuf_proc")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	proc.eventMaps = append(proc.eventMaps, procEventsMap)
	proc.eventFuncMaps[procEventsMap] = &ForkProcEvent{}

	return nil
}

func (proc *MProcProbe) Events() []*ebpf.Map {
	return proc.eventMaps
}

func init() {
	mod := &MProcProbe{}
	mod.name = "EBPFProbeProc"
	mod.mType = PROBE_TYPE_KPROBE
	Register(mod)
}
