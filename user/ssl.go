package user

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/szuwgh/pernis/common/vlog"
)

type SslDataEventT struct {
	Type        int32
	_           [4]byte
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	DataLen     int32
	Data        [4000]byte
	_           [4]byte
}

func AttachSSLUprobe() (err error) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	var objs ssl102aObjects
	if err := loadSsl102aObjects(&objs, nil); err != nil {
		vlog.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.1.1")
	if err != nil {
		return err
	}
	up1, err := ex.Uprobe("SSL_write", objs.UprobeSsL_write, nil)
	if err != nil {
		vlog.Fatalf("creating uprobe: %s", err)
	}
	up2, err := ex.Uretprobe("SSL_write", objs.UretprobeSslWrite, nil)
	if err != nil {
		vlog.Fatalf("creating uprobe: %s", err)
	}

	up3, err := ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
	if err != nil {
		vlog.Fatalf("creating uprobe: %s", err)
	}
	up4, err := ex.Uretprobe("SSL_read", objs.UretprobeSSL_read, nil)
	if err != nil {
		vlog.Fatalf("creating uprobe: %s", err)
	}

	defer up1.Close()
	defer up2.Close()
	defer up3.Close()
	defer up4.Close()

	rd, err := perf.NewReader(objs.TlsEvents, os.Getpagesize())
	if err != nil {
		vlog.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()
	go func() {
		<-stopper
		vlog.Println("Received signal, exiting program..")
		if err := rd.Close(); err != nil {
			vlog.Fatalf("closing perf event reader: %s", err)
		}
	}()
	vlog.Println("Tracing... Hit Ctrl-C to end.")
	vlog.Printf("   %-12s  %-s\n", "EVENT", "TIME(ns)")
	var event SslDataEventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			vlog.Printf("reading from perf event reader: %s", err)
			continue
		}
		if record.LostSamples != 0 {
			vlog.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			vlog.Printf("parsing perf event: %s", err)
			continue
		}

		vlog.Printf("%d,%s %d\n", event.Pid, string(event.Data[:]), event.DataLen)
	}

}
