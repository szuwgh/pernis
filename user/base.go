package user

import (
	"github.com/cilium/ebpf/rlimit"
	"github.com/szuwgh/pernis/common/vlog"
)

var objs = bpfObjects{}

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		vlog.Fatal(err)
	}
	//ebpf.LoadPinnedMap(fileName string, opts *ebpf.LoadPinOptions)

}
