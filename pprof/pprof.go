package pprof

import (
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/cespare/xxhash/v2"
	"github.com/google/pprof/profile"
	"github.com/klauspost/compress/gzip"
	"github.com/prometheus/prometheus/model/labels"
)

var (
	gzipWriterPool = sync.Pool{
		New: func() any {
			res, err := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
			if err != nil {
				panic(err)
			}
			return res
		},
	}
)

type ProfileBuilders struct {
	Builders   map[uint64]*ProfileBuilder
	SampleRate int64
}

func NewProfileBuilders(sampleRate int64) *ProfileBuilders {
	return &ProfileBuilders{Builders: make(map[uint64]*ProfileBuilder), SampleRate: sampleRate}
}

// 查找或返回一个进程数据构造器
func (b ProfileBuilders) BuilderForTarget(hash uint64, labels labels.Labels) *ProfileBuilder {
	res := b.Builders[hash]
	if res != nil {
		return res
	}
	// 创建并初始化一个构造器
	builder := &ProfileBuilder{
		locations:          make(map[string]*profile.Location),
		functions:          make(map[string]*profile.Function),
		sampleHashToSample: make(map[uint64]*profile.Sample),
		Labels:             labels,
		Profile: &profile.Profile{
			// 符号表
			Mapping: []*profile.Mapping{
				{
					ID: 1,
				},
			},
			TimeNanos: time.Now().UnixNano(),
		},
		tmpLocationIDs: make([]uint64, 0, 128),
		tmpLocations:   make([]*profile.Location, 0, 128),
	}
	res = builder
	// 完成键值对
	b.Builders[hash] = res
	return res
}

type ProfileBuilder struct {
	locations          map[string]*profile.Location
	functions          map[string]*profile.Function
	sampleHashToSample map[uint64]*profile.Sample
	Profile            *profile.Profile
	Labels             labels.Labels

	tmpLocations   []*profile.Location
	tmpLocationIDs []uint64
}

// 为进程数据构建器创建一个样本
func (p *ProfileBuilder) CreateSample(stacktrace []string, value uint64) {
	// 初始化样本
	sample := &profile.Sample{
		// 计算粗略的运行时长，采样数*采样周期
		Value: []int64{int64(value) * p.Profile.Period},
	}
	for _, s := range stacktrace {
		// 查找或添加符号对应的位置信息
		loc := p.addLocation(s)
		// 将位置信息添加进样本
		sample.Location = append(sample.Location, loc)
	}
	// 将样本添加进构造器
	p.Profile.Sample = append(p.Profile.Sample, sample)
}

// 为进程数据构建器进行样本累加或创建一个样本
func (p *ProfileBuilder) CreateSampleOrAddValue(stacktrace []string, value uint64) {
	scaledValue := int64(value) * p.Profile.Period
	p.tmpLocations = p.tmpLocations[:0]
	p.tmpLocationIDs = p.tmpLocationIDs[:0]
	for _, s := range stacktrace {
		loc := p.addLocation(s)
		p.tmpLocations = append(p.tmpLocations, loc)
		p.tmpLocationIDs = append(p.tmpLocationIDs, loc.ID)
	}
	h := xxhash.Sum64(uint64Bytes(p.tmpLocationIDs))
	// 进行累加
	sample := p.sampleHashToSample[h]
	if sample != nil {
		sample.Value[0] += scaledValue
		return
	}
	sample = &profile.Sample{
		Location: make([]*profile.Location, len(p.tmpLocations)),
		Value:    []int64{scaledValue},
	}
	copy(sample.Location, p.tmpLocations)
	p.sampleHashToSample[h] = sample
	p.Profile.Sample = append(p.Profile.Sample, sample)
}

func (p *ProfileBuilder) addLocation(function string) *profile.Location {
	loc, ok := p.locations[function]
	if ok {
		return loc
	}

	id := uint64(len(p.Profile.Location) + 1)
	loc = &profile.Location{
		ID:      id,
		Mapping: p.Profile.Mapping[0],
		Line: []profile.Line{
			{
				Function: p.addFunction(function),
			},
		},
	}
	p.Profile.Location = append(p.Profile.Location, loc)
	p.locations[function] = loc
	return loc
}

func (p *ProfileBuilder) addFunction(function string) *profile.Function {
	f, ok := p.functions[function]
	if ok {
		return f
	}

	id := uint64(len(p.Profile.Function) + 1)
	f = &profile.Function{
		ID:   id,
		Name: function,
	}
	p.Profile.Function = append(p.Profile.Function, f)
	p.functions[function] = f
	return f
}

func (p *ProfileBuilder) Write(dst io.Writer) (int64, error) {
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(dst)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	// 写入缓存
	err := p.Profile.WriteUncompressed(gzipWriter)
	if err != nil {
		return 0, fmt.Errorf("ebpf profile encode %w", err)
	}
	err = gzipWriter.Close()
	if err != nil {
		return 0, fmt.Errorf("ebpf profile encode %w", err)
	}
	return 0, nil
}

func uint64Bytes(s []uint64) []byte {
	if len(s) == 0 {
		return nil
	}
	var bs []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	hdr.Len = len(s) * 8
	hdr.Cap = hdr.Len
	hdr.Data = uintptr(unsafe.Pointer(&s[0]))
	return bs
}
