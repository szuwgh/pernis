package user

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type conn_info_evt -type msg_evt_data -type so_event -type upid_t -no-global-types -strip llvm-strip-12 -target amd64 bpf ../bpf/net/net.c -- -I../bpf/headers
