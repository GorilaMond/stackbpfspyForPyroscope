//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/go-kit/log"
	"github.com/google/pprof/profile"
	ebpfmetrics "github.com/grafana/pyroscope/ebpf/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"

	"github.com/go-kit/log/level"
	pushv1 "github.com/grafana/pyroscope/api/gen/proto/go/push/v1"
	"github.com/grafana/pyroscope/api/gen/proto/go/push/v1/pushv1connect"
	typesv1 "github.com/grafana/pyroscope/api/gen/proto/go/types/v1"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/pprof"
	"github.com/grafana/pyroscope/ebpf/sd"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"github.com/grafana/pyroscope/ebpf/symtab/elf"
	"github.com/prometheus/client_golang/prometheus"
	commonconfig "github.com/prometheus/common/config"
)

var configFile = flag.String("config", "", "config file path") // -config 参数解析单元 flag包用于参数解析，参数依次为 匹配项，默认值，注释
var server = flag.String("server", "http://localhost:4040", "")

var (
	config  *Config
	logger  log.Logger
	metrics *ebpfmetrics.Metrics
	session ebpfspy.Session
)

func main() {
	config = getConfig()
	// 创建客户端性能指标
	metrics = ebpfmetrics.New(prometheus.DefaultRegisterer)

	// 创建记录器并将输出流设定到标准错误
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))

	// 创建并设定目标查找器
	targetFinder, err := sd.NewTargetFinder(os.DirFS("/"), logger, convertTargetOptions())
	if err != nil {
		panic(fmt.Errorf("ebpf target finder create: %w", err))
	}
	// 根据config创建eBPF监测选项
	options := convertSessionOptions()
	// 创建eBPF监测会话
	session, err = ebpfspy.NewSession(
		logger,
		targetFinder,
		options,
	)
	// 开始eBPF监测
	err = session.Start()
	if err != nil {
		panic(err)
	}

	// 创建画像数据发送信道
	profiles := make(chan *pushv1.PushRequest, 128)
	go ingest(profiles)
	for {
		time.Sleep(5 * time.Second)

		// 收集画像数据传送给数据信道
		collectProfiles(profiles)

		// 以当前命名空间所有符合规则的进程更新目标查找器，并解析未知pid
		session.UpdateTargets(convertTargetOptions())
	}
}

// 收集数据并传给信道
func collectProfiles(profiles chan *pushv1.PushRequest) {
	// 创建进程数据构建器群
	builders := pprof.NewProfileBuilders(int64(config.SampleRate))
	// 设定数据提取函数
	err := session.CollectProfiles(func(target *sd.Target, stack []string, value uint64, pid uint32, aggregation ebpfspy.SampleAggregation) {
		// 获取进程哈希值和进程标签组
		labelsHash, labels := target.Labels()
		builder := builders.BuilderForTarget(labelsHash, labels)
		s := session.Scale()
		p := builder.Profile
		p.SampleType = []*profile.ValueType{{Type: s.Type, Unit: s.Unit}}
		p.Period = s.Period
		p.PeriodType = &profile.ValueType{Type: s.Type, Unit: s.Unit}
		// 若eBPF中对数据已经进行了累计
		if aggregation == ebpfspy.SampleAggregated {
			builder.CreateSample(stack, value)
		} else {
			// 否则，在用户态进行累计
			builder.CreateSampleOrAddValue(stack, value)
		}
	})

	if err != nil {
		panic(err)
	}
	level.Debug(logger).Log("msg", "ebpf collectProfiles done", "profiles", len(builders.Builders))

	for _, builder := range builders.Builders {
		// 将进程标签组转换为标准类型组
		protoLabels := make([]*typesv1.LabelPair, 0, builder.Labels.Len())
		for _, label := range builder.Labels {
			protoLabels = append(protoLabels, &typesv1.LabelPair{
				Name: label.Name, Value: label.Value,
			})
		}

		// 向缓存中写入样本数据
		buf := bytes.NewBuffer(nil)
		_, err := builder.Write(buf)
		if err != nil {
			panic(err)
		}

		// 创建一个push请求
		req := &pushv1.PushRequest{Series: []*pushv1.RawProfileSeries{{
			Labels: protoLabels,
			Samples: []*pushv1.RawSample{{
				RawProfile: buf.Bytes(),
			}},
		}}}
		select {
		// 传给信道
		case profiles <- req:
		// 传送失败则记录
		default:
			_ = level.Error(logger).Log("err", "dropping profile", "target", builder.Labels.String())
		}

	}

	if err != nil {
		panic(err)
	}
}

// 接收信道数据并发送
func ingest(profiles chan *pushv1.PushRequest) {
	httpClient, err := commonconfig.NewClientFromConfig(commonconfig.DefaultHTTPClientConfig, "http_playground")
	if err != nil {
		panic(err)
	}
	client := pushv1connect.NewPusherServiceClient(httpClient, *server)

	for {
		it := <-profiles
		res, err := client.Push(context.TODO(), connect.NewRequest(it))
		if err != nil {
			fmt.Println(err)
		}
		if res != nil {
			fmt.Println(res)
		}
	}

}

// 由当前命名空间所有符合规则的进程生成目标选项
func convertTargetOptions() sd.TargetsOptions {
	return sd.TargetsOptions{
		// 只监控给定目标
		// 设定为当前所有进程中满足规则的进程目标列表
		// 默认目标
		// pid->cid 映射表缓存大小
		TargetsOnly:        config.TargetsOnly,
		Targets:            relabelProcessTargets(getProcessTargets(), config.RelabelConfig),
		DefaultTarget:      config.DefaultTarget,
		ContainerCacheSize: config.ContainerCacheSize,
	}
}

func convertSessionOptions() ebpfspy.SessionOptions {
	return ebpfspy.SessionOptions{
		CollectUser:               config.CollectUser,
		CollectKernel:             config.CollectKernel,
		SampleRate:                config.SampleRate,
		UnknownSymbolAddress:      config.UnknownSymbolAddress,
		UnknownSymbolModuleOffset: config.UnknownSymbolModuleOffset,
		PythonEnabled:             config.PythonEnabled,
		Metrics:                   metrics,
		CacheOptions:              config.CacheOptions,
		BPFType:                   config.BPFType,
		BPFOption:                 config.BPFOption,
	}
}

func getConfig() *Config {
	flag.Parse()

	if *configFile == "" {
		panic("config file not specified") // 未设置时报错
	}
	var config = new(Config)
	*config = defaultConfig // 有默认值，由下面可知为json格式，所以配置文件内容可以是 "{}" （空的）
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(configBytes, config) // json格式解析，所以配置文件需为json格式
	if err != nil {
		panic(err)
	}
	return config
}

var defaultConfig = Config{
	CollectUser:               true,
	CollectKernel:             true,
	UnknownSymbolModuleOffset: true,
	UnknownSymbolAddress:      true,
	PythonEnabled:             true,
	CacheOptions: symtab.CacheOptions{
		SymbolOptions: symtab.SymbolOptions{
			GoTableFallback:    true,
			PythonFullFilePath: false,
			DemangleOptions:    elf.DemangleFull,
		},
		PidCacheOptions: symtab.GCacheOptions{
			Size:       239,
			KeepRounds: 8,
		},
		BuildIDCacheOptions: symtab.GCacheOptions{
			Size:       239,
			KeepRounds: 8,
		},
		SameFileCacheOptions: symtab.GCacheOptions{
			Size:       239,
			KeepRounds: 8,
		},
	},
	SampleRate:         97,
	TargetsOnly:        true,
	DefaultTarget:      nil,
	ContainerCacheSize: 1024,
	RelabelConfig:      nil,
	BPFType:            "on-cpu",
	BPFOption:          "49",
}

type Config struct {
	CollectUser               bool
	CollectKernel             bool
	UnknownSymbolModuleOffset bool
	UnknownSymbolAddress      bool
	PythonEnabled             bool
	CacheOptions              symtab.CacheOptions
	SampleRate                int
	TargetsOnly               bool
	DefaultTarget             map[string]string
	ContainerCacheSize        int
	RelabelConfig             []*RelabelConfig
	BPFType                   string
	BPFOption                 string
}

type RelabelConfig struct {
	SourceLabels []string

	Separator string

	Regex string

	TargetLabel string `yaml:"target_label,omitempty"`

	Replacement string `yaml:"replacement,omitempty"`

	Action string
}

// 由当前命名空间的所有进程生成已发现目标的列表
func getProcessTargets() []sd.DiscoveryTarget {
	dir, err := os.ReadDir("/proc")
	if err != nil {
		panic(err)
	}
	var res []sd.DiscoveryTarget
	for _, entry := range dir {
		if !entry.IsDir() {
			continue
		}
		spid := entry.Name()
		pid, err := strconv.ParseUint(spid, 10, 32)
		if err != nil {
			continue
		}
		if pid == 0 {
			continue
		}
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%s/cwd", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading cwd", "pid", spid)
			}
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading exe", "pid", spid)
			}
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading comm", "pid", spid)
			}
		}
		cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%s/cgroup", spid))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				_ = level.Error(logger).Log("err", err, "msg", "reading cgroup", "pid", spid)
			}
		}
		// 初始进程元数据
		target := sd.DiscoveryTarget{
			"__process_pid__":       spid,
			"__meta_process_cwd":    cwd,
			"__meta_process_exe":    exe,
			"__meta_process_comm":   string(comm),
			"__meta_process_cgroup": string(cgroup),
		}
		_ = level.Debug(logger).Log("msg", "process target", "target", target.DebugString())
		res = append(res, target)
	}
	return res
}

// 对已找到目标列表根据配置进行过滤
func relabelProcessTargets(targets []sd.DiscoveryTarget, cfg []*RelabelConfig) []sd.DiscoveryTarget {
	var promConfig []*relabel.Config
	for _, c := range cfg {
		var srcLabels model.LabelNames
		for _, label := range c.SourceLabels {
			srcLabels = append(srcLabels, model.LabelName(label))
		}
		promConfig = append(promConfig, &relabel.Config{
			SourceLabels: srcLabels,
			Separator:    c.Separator,
			Regex:        relabel.MustNewRegexp(c.Regex),
			TargetLabel:  c.TargetLabel,
			Replacement:  c.Replacement,
			Action:       relabel.Action(c.Action),
		})
	}
	var res []sd.DiscoveryTarget
	for _, target := range targets {
		// lbls对应一个进程
		lbls := labels.FromMap(target)
		// 对进程标签进行规则匹配
		lbls, keep := relabel.Process(lbls, promConfig...)
		// 规则返回不保留，继续下次
		if !keep {
			continue
		}
		// 否则，添加到返回列表中
		tt := sd.DiscoveryTarget(lbls.Map())
		_ = level.Debug(logger).Log("msg", "relabelled process", "target", tt.DebugString())
		res = append(res, tt)
	}
	return res
}
