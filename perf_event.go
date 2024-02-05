//go:build linux

package ebpfspy

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type perfEvent struct {
	fd    int
	ioctl bool
	link  *link.RawLink
}

// 创建perf事件
func newPerfEvent(cpu int, sampleRate int) (*perfEvent, error) {
	var (
		fd  int
		err error
	)
	// perf事件选项
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitFreq,
		Sample: uint64(sampleRate),
	}
	fd, err = unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open perf event: %w", err)
	}
	// 可以直接返回局部变量的地址
	// golang编译器会自动进行逃逸分析，决定将局部变量放在栈还是堆中
	return &perfEvent{fd: fd}, nil
}

// 关闭perf事件
func (pe *perfEvent) Close() error {
	_ = syscall.Close(pe.fd)
	if pe.link != nil {
		_ = pe.link.Close()
	}
	return nil
}

// 将perf事件与eBPF函数绑定
func (pe *perfEvent) attachPerfEvent(prog *ebpf.Program) error {
	// 创建连接
	err := pe.attachPerfEventLink(prog)
	if err == nil {
		return nil
	}
	//绑定事件
	return pe.attachPerfEventIoctl(prog)
}

func (pe *perfEvent) attachPerfEventIoctl(prog *ebpf.Program) error {
	var err error
	//将perf事件与ebpf程序绑定
	err = unix.IoctlSetInt(pe.fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD())
	if err != nil {
		return fmt.Errorf("setting perf event bpf program: %w", err)
	}
	//暂停perf事件
	if err = unix.IoctlSetInt(pe.fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return fmt.Errorf("enable perf event: %w", err)
	}
	pe.ioctl = true
	return nil
}

func (pe *perfEvent) attachPerfEventLink(prog *ebpf.Program) error {
	var err error
	opts := link.RawLinkOptions{
		Target:  pe.fd,
		Program: prog,
		Attach:  ebpf.AttachPerfEvent,
	}

	pe.link, err = link.AttachRawLink(opts)
	if err != nil {
		return fmt.Errorf("attach raw link: %w", err)
	}

	return nil
}
