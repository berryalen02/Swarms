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

type MJavaRasp struct {
	Module
	javaManager        *manager.Manager
	javaManagerOptions manager.Options
	eventFuncMaps      map[*ebpf.Map]IEventStruct
	eventMaps          []*ebpf.Map
}

// 对象初始化
func (mjava *MJavaRasp) Init(ctx context.Context, logger *log.Logger) error {
	mjava.Module.Init(ctx, logger)
	mjava.Module.SetChild(mjava)
	mjava.eventMaps = make([]*ebpf.Map, 0, 2)
	mjava.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (mjava *MJavaRasp) Start() error {
	if err := mjava.start(); err != nil {
		return err
	}

	return nil
}

func (mjava *MJavaRasp) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/java_exec_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	mjava.setupManagers()

	// initialize the bootstrap manager
	if err := mjava.javaManager.InitWithOptions(bytes.NewReader(javaBuf), mjava.javaManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := mjava.javaManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = mjava.initDecodeFun()
	if err != nil {
		return err
	}

	mjava.logger.Printf("process pid: %d\n", os.Getpid())

	return nil
}

func (mjava *MJavaRasp) Close() error {
	if err := mjava.javaManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (mjava *MJavaRasp) setupManagers() {
	mjava.javaManager = &manager.Manager{
		/*
			openjdk version "1.8.0_292"
			OpenJDK Runtime Environment (build 1.8.0_292-8u292-b10-0ubuntu1-b10)
			OpenJDK 64-Bit Server VM (build 25.292-b10, mixed mode)
		*/
		//ex, err := link.OpenExecutable("/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so")

		// sub_19C30  == JDK_execvpe(p->mode, p->argv[0], p->argv, p->envv);
		// 		md5sum : 38590d0382d776234201996e99487110  /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/JDK_execvpe",
				EbpfFuncName:     "java_JDK_execvpe",
				AttachToFuncName: "JDK_execvpe",
				UprobeOffset:     0x19C30,
				BinaryPath:       "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "jdk_execvpe_events",
			},
		},
	}

	mjava.javaManagerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (mjava *MJavaRasp) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	es, found := mjava.DecodeFun(em)
	if !found {
		err = fmt.Errorf("can't found decode function :%s, address:%p", em.String(), em)
		return
	}
	result, err = mjava.EventsDecode(b, es)
	if err != nil {
		return
	}
	return
}

func (mjava *MJavaRasp) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := mjava.eventFuncMaps[em]
	return fun, found
}

func (mjava *MJavaRasp) initDecodeFun() error {
	//eventMap 与解码函数映射
	mjava.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	javaEventMap, found, err := mjava.javaManager.GetMap("jdk_execvpe_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:jdk_execvpe_events")
	}
	mjava.eventMaps = append(mjava.eventMaps, javaEventMap)
	mjava.eventFuncMaps[javaEventMap] = &JavaJDKExecPeEvent{}
	return nil
}

func (mjava *MJavaRasp) Events() []*ebpf.Map {
	return mjava.eventMaps
}

func init() {
	mod := &MJavaRasp{}
	mod.name = "EBPFProbeUJavaRASP"
	mod.mType = PROBE_TYPE_UPROBE
	Register(mod)
}
