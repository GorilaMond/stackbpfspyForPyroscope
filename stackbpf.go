package ebpfspy

import (
	"github.com/cilium/ebpf"
)

type Scale struct {
	Type   string
	Unit   string
	Period int64
}

type StackBPF interface {
	Config(string) error
	Scale() Scale

	Load() error
	Attach() error
	Detach()
	Remove()

	Events() *ebpf.Map
	Counts() *ebpf.Map
	Pids() *ebpf.Map
	Stacks() *ebpf.Map
	Progs() *ebpf.Map

	DisassociateCtty() *ebpf.Program
	Exec() *ebpf.Program
}
