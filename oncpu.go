package ebpfspy

import (
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/grafana/pyroscope/ebpf/cpuonline"
	"github.com/grafana/pyroscope/ebpf/pyrobpf"
)

type OnCPUStackBPF struct {
	bpf        pyrobpf.ProfileObjects
	perfEvents []*perfEvent
	sampleRate int
}

func (ob *OnCPUStackBPF) Config(cfg string) error {
	sampleRate, err := strconv.ParseUint(cfg, 10, 32)
	ob.sampleRate = int(sampleRate)
	return err
}

func (ob *OnCPUStackBPF) Scale() Scale {
	return Scale{
		Type:   "OnCPUTime",
		Unit:   "nanoseconds",
		Period: time.Second.Nanoseconds() / int64(ob.sampleRate),
	}
}

func (ob *OnCPUStackBPF) Load() error {
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: true,
		},
	}
	return pyrobpf.LoadProfileObjects(&ob.bpf, opts)
}

func (ob *OnCPUStackBPF) Attach() error {
	var cpus []uint
	var err error
	if cpus, err = cpuonline.Get(); err != nil {
		return fmt.Errorf("get cpuonline: %w", err)
	}
	// 每cpu创建一个perf事件并绑定eBPF
	for _, cpu := range cpus {
		pe, err := newPerfEvent(int(cpu), ob.sampleRate)
		if err != nil {
			return fmt.Errorf("new perf event: %w", err)
		}
		ob.perfEvents = append(ob.perfEvents, pe)

		err = pe.attachPerfEvent(ob.bpf.DoPerfEvent)
		if err != nil {
			return fmt.Errorf("attach perf event: %w", err)
		}
	}
	return nil
}

func (ob *OnCPUStackBPF) Detach() {
	for _, pe := range ob.perfEvents {
		_ = pe.Close()
	}
	ob.perfEvents = nil
}

func (ob *OnCPUStackBPF) Remove() {
	_ = ob.bpf.Close()
}

func (ob *OnCPUStackBPF) Events() *ebpf.Map {
	return ob.bpf.ProfileMaps.Events
}
func (ob *OnCPUStackBPF) Counts() *ebpf.Map {
	return ob.bpf.ProfileMaps.Counts
}
func (ob *OnCPUStackBPF) Pids() *ebpf.Map {
	return ob.bpf.ProfileMaps.Pids
}
func (ob *OnCPUStackBPF) Stacks() *ebpf.Map {
	return ob.bpf.ProfileMaps.Stacks
}
func (ob *OnCPUStackBPF) Progs() *ebpf.Map {
	return ob.bpf.ProfileMaps.Progs
}

func (ob *OnCPUStackBPF) DisassociateCtty() *ebpf.Program {
	return ob.bpf.DisassociateCtty
}
func (ob *OnCPUStackBPF) Exec() *ebpf.Program {
	return ob.bpf.Exec
}
