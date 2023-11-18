package user

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type SslDataEventT struct {
	Type        int32
	_           [4]byte
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	Data        [4000]byte
	DataLen     int32
	_           [4]byte
}

func AttachSSLUprobe() (err error) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.1.1")
	if err != nil {
		return err
	}
	up1, err := ex.Uprobe("SSL_write", objs.UprobeSsL_write, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	up2, err := ex.Uretprobe("SSL_write", objs.UretprobeSslWrite, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}

	defer up1.Close()
	defer up2.Close()

	rd, err := perf.NewReader(objs.TlsEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()
	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()
	fmt.Println("Tracing... Hit Ctrl-C to end.")
	fmt.Printf("   %-12s  %-s\n", "EVENT", "TIME(ns)")
	var event SslDataEventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}
		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("%d,%s\n", event.Pid, string(event.Data[:event.DataLen]))
	}

}