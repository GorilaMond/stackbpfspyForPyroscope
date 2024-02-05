package ebpfspy

import (
	"fmt"
	"os"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/grafana/pyroscope/ebpf/offcpubpf"
)

type OffCPUStackBPF struct {
	bpf         offcpubpf.ProfileObjects
	targetEvent link.Link
}

func (ob *OffCPUStackBPF) Config(cfg string) error {
	return nil
}

func (ob *OffCPUStackBPF) Scale() Scale {
	return Scale{
		Type:   "OffCPUTime",
		Unit:   "nanoseconds",
		Period: 1 << 20,
	}
}

func (ob *OffCPUStackBPF) Load() error {
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: true,
		},
	}
	return offcpubpf.LoadProfileObjects(&ob.bpf, opts)
}

func (ob *OffCPUStackBPF) Attach() error {
	ksymsB, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return fmt.Errorf("connot open kallsyms")
	}
	ksyms := string(ksymsB)
	reg := regexp.MustCompile(`finish_task_switch[^\s]*`)
	symbol := reg.FindString(ksyms)
	fmt.Print(symbol, "\n")
	if symbol == "" {
		return fmt.Errorf("not fount symbol finish_task_switch*")
	}
	kp, err := link.Kprobe(symbol, ob.bpf.DoOffCpu, nil)
	if err != nil {
		return fmt.Errorf("link kprobe %s: %w", symbol, err)
	}
	ob.targetEvent = kp
	return nil
}

func (ob *OffCPUStackBPF) Detach() {
	_ = ob.targetEvent.Close()
	ob.targetEvent = nil
}

func (ob *OffCPUStackBPF) Remove() {
	_ = ob.bpf.Close()
}

func (ob *OffCPUStackBPF) Events() *ebpf.Map {
	return ob.bpf.ProfileMaps.Events
}
func (ob *OffCPUStackBPF) Counts() *ebpf.Map {
	return ob.bpf.ProfileMaps.Counts
}
func (ob *OffCPUStackBPF) Pids() *ebpf.Map {
	return ob.bpf.ProfileMaps.Pids
}
func (ob *OffCPUStackBPF) Stacks() *ebpf.Map {
	return ob.bpf.ProfileMaps.Stacks
}
func (ob *OffCPUStackBPF) Progs() *ebpf.Map {
	return ob.bpf.ProfileMaps.Progs
}

func (ob *OffCPUStackBPF) DisassociateCtty() *ebpf.Program {
	return ob.bpf.DisassociateCtty
}
func (ob *OffCPUStackBPF) Exec() *ebpf.Program {
	return ob.bpf.Exec
}
