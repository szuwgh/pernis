package main

import (
	//_ "github.com/cilium/ebpf/cmd/bpf2go"
	"github.com/szuwgh/pernis/cmd"
)

// 流量统计 限流 嗅探 回放
func main() {
	cmd.Execute()
}
