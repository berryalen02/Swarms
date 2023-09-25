package user

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"swarms/assets"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type MBPFCallProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (BPFCall *MBPFCallProbe) Init(ctx context.Context, logger *log.Logger) error {
	BPFCall.Module.Init(ctx, logger)
	BPFCall.Module.SetChild(BPFCall)
	BPFCall.eventMaps = make([]*ebpf.Map, 0, 2)
	BPFCall.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (BPFCall *MBPFCallProbe) Start() error {
	if err := BPFCall.start(); err != nil {
		return err
	}
	return nil
}

func (BPFCall *MBPFCallProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/bpf_call_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	BPFCall.setupManagers()

	// perfMap 事件处理函数设定
	perfMap, ok := BPFCall.bpfManager.GetPerfMap("events")
	if !ok {
		return errors.New("couldn't find events perf map")
	}

	perfMap.PerfMapOptions = manager.PerfMapOptions{
		PerfRingBufferSize: 1 * os.Getpagesize(),
		DataHandler:        BPFCall.dataHandler,
		LostHandler:        BPFCall.lostEventsHandle,
	}

	// initialize the bootstrap manager
	if err := BPFCall.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), BPFCall.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := BPFCall.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = BPFCall.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (BPFCall *MBPFCallProbe) Close() error {
	if err := BPFCall.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (BPFCall *MBPFCallProbe) setupManagers() {
	BPFCall.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "tracepoint/syscalls/sys_enter_bpf",
				EbpfFuncName:     "tracepoint_sys_enter_bpf",
				AttachToFuncName: "sys_enter_bpf",
			},
		},

		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{
					Name: "events",
				},
			},
		},
	}

	BPFCall.bpfManagerOptions = manager.Options{
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
		MapSpecEditors: map[string]manager.MapSpecEditor{
			"events": {
				Type:       ebpf.PerfEventArray,
				MaxEntries: uint32(64),
			},
		},
	}
}

func (BPFCall *MBPFCallProbe) dataHandler(cpu int, data []byte, perfmap *manager.PerfMap, manager *manager.Manager) {
	bpfEvent := &BpfCallEvent{}
	err := bpfEvent.Decode(data)
	if err != nil {
		BPFCall.logger.Fatalf("decode error:%v", err)
		return
	}

	//自定义上报策略，或者写入到日志中心
	BPFCall.Write(fmt.Sprintf("BPFCALL EVENT CPU:%d, %s", cpu, bpfEvent.String()))
}

// TODO 事件丢失统计
func (BPFCall *MBPFCallProbe) lostEventsHandle(CPU int, count uint64, perfMap *manager.PerfMap, manager *manager.Manager) {
	// TODO  参考 datadog-agent的 pkg/security/probe/perf_buffer_monitor.go 实现
	// perfBufferMonitor.CountLostEvent(count, perfMap, CPU)
}

func (BPFCall *MBPFCallProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := BPFCall.eventFuncMaps[em]
	return fun, found
}

func (BPFCall *MBPFCallProbe) initDecodeFun() error {
	return nil
}

func (BPFCall *MBPFCallProbe) Events() []*ebpf.Map {
	return BPFCall.eventMaps
}

func init() {
	mod := &MBPFCallProbe{}
	mod.name = "EBPFProbeBPFCall"
	mod.mType = PROBE_TYPE_TP
	Register(mod)
}
