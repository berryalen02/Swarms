package user

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"swarms/user/kafka"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type IModule interface {
	// Init 初始化
	Init(context.Context, *log.Logger) error

	// Name 获取当前module的名字
	Name() string

	// Run 事件监听感知
	Run() error

	// Start 启动模块
	Start() error

	// Stop 停止模块
	Stop() error

	// Close 关闭退出
	Close() error

	SetChild(module IModule)

	Decode(*ebpf.Map, []byte) (string, error)

	Events() []*ebpf.Map

	DecodeFun(p *ebpf.Map) (IEventStruct, bool)
}

type Module struct {
	opts   *ebpf.CollectionOptions
	reader []IClose
	ctx    context.Context
	logger *log.Logger
	child  IModule
	// probe的名字
	name string

	// module的类型，uprobe,kprobe等
	mType string
}

// Init 对象初始化
func (m *Module) Init(ctx context.Context, logger *log.Logger) {
	m.ctx = ctx
	m.logger = logger
	return
}

func (m *Module) SetChild(module IModule) {
	m.child = module
}

func (m *Module) Start() error {
	panic("Module.Start() not implemented yet")
}

func (m *Module) Events() []*ebpf.Map {
	panic("Module.Events() not implemented yet")
}

func (m *Module) DecodeFun(p *ebpf.Map) (IEventStruct, bool) {
	panic("Module.DecodeFun() not implemented yet")
}

func (m *Module) Name() string {
	return m.name
}

func (m *Module) Run() error {
	//  start
	err := m.child.Start()
	if err != nil {
		return err
	}

	err = m.readEvents()
	if err != nil {
		return err
	}

	go func() {
		m.run()
	}()
	return nil
}
func (m *Module) Stop() error {
	return nil
}

// Stop shuts down Module
func (m *Module) run() {
	for {
		select {
		case _ = <-m.ctx.Done():
			err := m.child.Stop()
			if err != nil {
				m.logger.Fatalf("stop Module:%s error:%v.", m.child.Name(), err)
			}
			return
		}
	}
}

func (m *Module) readEvents() error {
	var errChan = make(chan error, 8)
	for _, event := range m.child.Events() {
		switch {
		case event.Type() == ebpf.RingBuf:
			go m.ringbufEventReader(errChan, event)
		case event.Type() == ebpf.PerfEventArray:
			go m.perfEventReader(errChan, event)
		default:
			errChan <- fmt.Errorf("Not support mapType:%s , mapinfo:%s", event.Type().String(), event.String())
		}
	}

	for {
		select {
		case err := <-errChan:
			return err
		}
	}
}

func (m *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := perf.NewReader(em, os.Getpagesize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <-m.ctx.Done():
			log.Printf("readEvent recived close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			errChan <- fmt.Errorf("reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		var result string
		result, err = m.child.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("this.child.decode error:%v", err)
			continue
		}

		// 上报数据
		m.Write(result)
	}
}

func (m *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <-m.ctx.Done():
			m.logger.Printf("readEvent recived close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				m.logger.Println("Received signal, exiting..")
				return
			}
			errChan <- fmt.Errorf("reading from ringbuf reader: %s", err)
			return
		}

		var result string
		result, err = m.child.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("this.child.decode error:%v", err)
			continue
		}

		// 上报数据
		m.Write(result)
	}
}

func (e *Module) EventsDecode(payload []byte, es IEventStruct) (s string, err error) {
	te := es.Clone()
	err = te.Decode(payload)
	if err != nil {
		return
	}
	s = te.String()
	return
}

func (m *Module) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	es, found := m.child.DecodeFun(em)
	if !found {
		err = fmt.Errorf("can't found decode function :%s, address:%p", em.String(), em)
		return
	}
	result, err = m.EventsDecode(b, es)
	if err != nil {
		return
	}
	return
}

// 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (m *Module) Write(result string) {
	s := fmt.Sprintf("probeName:%s, probeTpye:%s, %s", m.name, m.mType, result)
	m.logger.Println(s)

	err := kafka.Producer2Kafka(kafka.Broker, kafka.Topic, result)
	if err != nil {
		fmt.Println("produce failed, err:", err)
	}
}
