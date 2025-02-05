package user

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	//"github.com/cilium/ebpf/ringbuf"
	//"github.com/szuwgh/pernis/common/byteorder"
	"github.com/szuwgh/pernis/common/vlog"
	"github.com/szuwgh/pernis/network"
	"golang.org/x/sys/unix"

	//"slices"
	"time"
	//"reflect"
	//"unsafe"
)

const ETH0 = "ens33"

const (
	SO_DETACH_FILTER = 27
	SO_BINDTODEVICE  = 25
)

const (
	ConnTypeConnect = iota
	ConnTypeClose
	ConnTypProtocolInfer
)

type Connection struct {
	LocalIp    network.IpAddr
	RemoteIp   network.IpAddr
	LocalPort  network.Port
	RemotePort network.Port
	Protocol   int32
	reqStream  *network.StreamBuffer
	respStream *network.StreamBuffer
	requests   []*network.GrabHttpRequest
	response   []*network.GrabHttpResponse
	tempMsgEvt []*bpfMsgEvtData
	connTime   uint64
	closeTime  uint64
	isClose    bool
	chainConn  []*Connection // 具有相同的文件描述符 sockfd
}

func (c *Connection) protocol() string {
	switch c.Protocol {
	case 0:
		return "unset"
	case 1:
		return "unknown"
	case 2:
		return "http"
	case 3:
		return "http2"
	}
	return "unknown"
}

func (c *Connection) uniqueIdent() string {
	return fmt.Sprintf("%d%d%d%d", c.LocalIp.Ip(), c.LocalPort, c.RemoteIp.Ip(), c.RemotePort)
}

// 是否是相同的连接
func (c *Connection) IsSameConn(o *Connection) bool {
	return c.LocalIp.Ip() == o.LocalIp.Ip() && c.RemoteIp.Ip() == o.RemoteIp.Ip() && c.RemotePort == o.RemotePort && c.LocalPort == o.LocalPort
}

func (c *Connection) match() []record {
	if len(c.requests) == 0 || len(c.response) == 0 {
		return nil
	}
	rec := record{}
	records := make([]record, 0)
	for len(c.response) > 0 {
		var req *network.GrabHttpRequest
		if len(c.requests) == 0 {
			req = nil
		} else {
			req = c.requests[0]
		}

		resp := c.response[0]
		if req != nil && req.Timestamp() < resp.Timestamp() {
			rec.req = req
			c.requests = c.requests[1:]
		} else {
			if rec.req != nil {
				rec.resp = resp
				records = append(records, rec)
				rec = record{}
			}
			c.response = c.response[1:]
		}
	}
	return records
}

type record struct {
	req  *network.GrabHttpRequest
	resp *network.GrabHttpResponse
}

type SoEvent struct {
	SrcAddr       uint32
	DstAddr       uint32
	SrcPort       uint16
	DstPort       uint16
	PayloadLength uint32
}

func AttachSysConnectKprobe() (err error) {
	p := newProcess()
	p.run()
	var objs = bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		vlog.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// kp, err := link.Kprobe("__sys_connect", objs.KprobeSysConnect, nil)
	// if err != nil {
	// 	vlog.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp.Close()

	// tpc1, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	// if err != nil {
	// 	vlog.Fatalf("opening tracepoint: %s", err)
	// }
	// defer tpc1.Close()

	// tpc, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.TracepointSyscallsSysExitConnect, nil)
	// if err != nil {
	// 	vlog.Fatalf("opening tracepoint: %s", err)
	// }
	// defer tpc.Close()

	tpc1, err := link.Tracepoint("syscalls", "sys_enter_accept4", objs.TracepointSyscallsSysEnterAccept4, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tpc1.Close()

	tpc, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TracepointSyscallsSysExitAccept4, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tpc.Close()

	tp1, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TracepointSyscallsSysEnterRead, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tp1.Close()

	tp2, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TracepointSyscallsSysExitRead, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tp2.Close()

	tp3, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSyscallsSysEnterWrite, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tp3.Close()

	tp4, err := link.Tracepoint("syscalls", "sys_exit_write", objs.TracepointSyscallsSysExitWrite, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tp4.Close()

	tp5, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TracepointSyscallsSysEnterClose, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tp5.Close()

	tp6, err := link.Tracepoint("syscalls", "sys_exit_close", objs.TracepointSyscallsSysExitClose, nil)
	if err != nil {
		vlog.Fatalf("opening tracepoint: %s", err)
	}
	defer tp6.Close()

	connEvtReader, err := perf.NewReader(objs.ConnEvtRb, os.Getpagesize()) //ringbuf.NewReader(objs.ConnEvtRb)
	if err != nil {
		vlog.Fatal("new connEvtReader perf err:", err)
		return
	}
	go func() {
		defer connEvtReader.Close()
		for {
			record, err := connEvtReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					vlog.Println("[connEvtReader] Received signal, exiting..")
					continue
				}
				vlog.Printf("[connEvtReader] reading from reader: %s\n", err)
				continue
			}
			var event bpfConnInfoEvt
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				continue
			}
			p.connEvt <- &event
		}
	}()
	msgEvtReader, err := perf.NewReader(objs.MsgEvtRb, os.Getpagesize()) //ringbuf.NewReader(objs.ConnEvtRb)
	if err != nil {
		vlog.Fatal("new connEvtReader perf err:", err)
		return
	}
	go func() {
		defer msgEvtReader.Close()
		for {
			record, err := msgEvtReader.Read()
			if err != nil {
				vlog.Println(err)
				if errors.Is(err, perf.ErrClosed) {
					vlog.Println("[connEvtReader] Received signal, exiting..")
					continue
				}
				vlog.Printf("[connEvtReader] reading from reader: %s\n", err)
				continue
			}
			rawSample := record.RawSample
			var evtData bpfMsgEvtData
			// 填充基础字段
			buffer := bytes.NewReader(rawSample)
			if err := binary.Read(buffer, binary.LittleEndian, &evtData.Meta); err != nil {
				vlog.Println(err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, &evtData.BufSize); err != nil {
				vlog.Println(err)
				continue
			}
			if err := binary.Read(buffer, binary.LittleEndian, evtData.Msg[:evtData.BufSize]); err != nil {
				vlog.Println(err)
				continue
			}
			p.msgEvt <- &evtData
		}
	}()
	select {}
	return nil
}

func int8ArrayToStringNoCopy(msg []int8) string {
	byteSlice := unsafe.Slice((*byte)(unsafe.Pointer(&msg[0])), len(msg))
	return string(byteSlice)
}

func int8ArrayToByteNoCopy(msg []int8) []byte {
	byteSlice := unsafe.Slice((*byte)(unsafe.Pointer(&msg[0])), len(msg))
	return byteSlice
}

// func AttachSocket() error {
// 	stopper := make(chan os.Signal, 1)
// 	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		vlog.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// 	sockFD, err := attachSocketFilter(ETH0, objs.bpfPrograms.SocketHander.FD())
// 	if err != nil {
// 		vlog.Fatalf("attach socket filter: %v", err)
// 	}

// 	defer syscall.Close(sockFD)
// 	// ticker := time.NewTicker(2 * time.Second)
// 	// defer ticker.Stop()
// 	// rd, err := ringbuf.NewReader(objs.Httpevent)
// 	// if err != nil {
// 	// 	vlog.Fatalf("opening ringbuf reader: %s", err)
// 	// }
// 	//defer rd.Close()
// 	go func() {
// 		<-stopper
// 		vlog.Println("Received signal, exiting program..")
// 		if err := detach(sockFD); err != nil {
// 			vlog.Fatal(err)
// 		}
// 		os.Exit(0)
// 	}()

// 	//vlog.Println("Waiting for events..")

// 	// bpfEvent is generated by bpf2go.

// 	rd, err := perf.NewReader(objs.Httpevent, os.Getpagesize())
// 	if err != nil {
// 		vlog.Fatalf("creating perf event reader: %s", err)
// 	}
// 	defer rd.Close()
// 	go func() {
// 		<-stopper
// 		vlog.Println("Received signal, exiting program..")
// 		if err := rd.Close(); err != nil {
// 			vlog.Fatalf("closing perf event reader: %s", err)
// 		}
// 	}()
// 	vlog.Println("Tracing... Hit Ctrl-C to end.")
// 	//vlog.Printf("   %-12s  %-s\n", "EVENT", "TIME(ns)")
// 	var event SoEvent

// 	for {
// 		record, err := rd.Read()
// 		if err != nil {
// 			if errors.Is(err, perf.ErrClosed) {
// 				return err
// 			}
// 			vlog.Printf("reading from perf event reader: %s", err)
// 			continue
// 		}
// 		if record.LostSamples != 0 {
// 			vlog.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
// 			continue
// 		}

// 		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
// 			vlog.Printf("parsing perf event: %s", err)
// 			continue
// 		}
// 		vlog.Printf("saddr:%s:%d -> addr: %s:%d \n", intToIP(event.SrcAddr), event.SrcPort, intToIP(event.DstAddr), event.DstPort)
// 		vlog.Printf("%s\n", record.RawSample[54+16:])

// 	}
// }

func detach(sockFD int) error {
	err := unix.SetsockoptInt(sockFD, unix.SOL_SOCKET, SO_DETACH_FILTER, 0)
	if err != nil {
		return fmt.Errorf("SetSockOpt with SO_DETACH_FILTER failed: %v", err)
	}

	return nil
}

func attachSocketFilter(deviceName string, ebpfProgFD int) (int, error) {
	_, err := net.InterfaceByName(deviceName)
	if err != nil {
		return -1, err
	}

	var sockFD int

	sockFD, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}

	err = unix.SetsockoptString(sockFD, unix.SOL_SOCKET, SO_BINDTODEVICE, deviceName)
	if err != nil {
		return -1, err
	}

	if err = syscall.SetsockoptInt(sockFD, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, ebpfProgFD); err != nil {
		return -1, err
	}

	// sll := syscall.SockaddrLinklayer{
	// 	Ifindex:  netInterface.Index,
	// 	Protocol: htons(syscall.ETH_P_ALL),
	// }
	// if err = syscall.Bind(sockFD, &sll); err != nil {
	// 	return -1, err
	// }
	return sockFD, nil
}

type Process struct {
	connEvt chan *bpfConnInfoEvt
	msgEvt  chan *bpfMsgEvtData
	pes     *pernis
}

func newProcess() *Process {
	p := &Process{
		connEvt: make(chan *bpfConnInfoEvt),
		msgEvt:  make(chan *bpfMsgEvtData),
		pes:     NewPernis(),
	}
	return p
}

func (p *Process) run() {
	go func() {
		for {
			select {
			case event := <-p.connEvt:
				tgidFd := uint64(event.Info.ConnId.Upid.Tgid)<<32 | uint64(event.Info.ConnId.Fd)
				switch event.Info.Ctype {
				case ConnTypeConnect:
					//conn := pes.GetConn(tgidFd)
					conn := &Connection{
						LocalIp:    network.ToIpAddr(event.Info.Saddr.In4.SinAddr.S_addr),
						RemoteIp:   network.ToIpAddr(event.Info.Daddr.In4.SinAddr.S_addr),
						LocalPort:  network.Port(event.Info.Saddr.In4.SinPort),
						RemotePort: network.Port(event.Info.Daddr.In4.SinPort),
						reqStream:  &network.StreamBuffer{},
						respStream: &network.StreamBuffer{},
						connTime:   event.Ts,
					}
					//vlog.Println("connect", conn.LocalIp.String(), conn.LocalPort, conn.RemoteIp.String(), conn.RemotePort, conn.protocol(), event.Ts)
					p.pes.AddConn(tgidFd, conn)
				case ConnTypeClose:
					conn := p.pes.GetConnWithTs(tgidFd, event.Ts)
					//vlog.Println("close", conn.LocalIp.String(), conn.LocalPort, conn.RemoteIp.String(), conn.RemotePort, conn.protocol(), event.Ts)
					if conn != nil {
						conn.closeTime = event.Ts
						go func() {
							timer := time.NewTimer(1 * time.Second)
							defer timer.Stop()
							runtime.Gosched()
							<-timer.C
							conn.isClose = true
						}()
					}
				case ConnTypProtocolInfer:
					conn := p.pes.GetConnWithTs(tgidFd, event.Ts)
					if conn != nil {
						conn.Protocol = event.Info.Protocol
						//vlog.Println("infer", conn.LocalIp.String(), conn.LocalPort, conn.RemoteIp.String(), conn.RemotePort, conn.protocol(), event.Ts)
						if conn.protocol() == "http" {
							if len(conn.tempMsgEvt) > 0 {
								for _, event := range conn.tempMsgEvt {
									if event.Meta.MsgType == 1 { //请求
										conn.reqStream.Add(event.Meta.Ts, event.Meta.Seq, int8ArrayToByteNoCopy(event.Msg[:event.BufSize])) //buffers.Write(int8ArrayToByteNoCopy(evtData.Msg[:evtData.BufSize]))
									} else if event.Meta.MsgType == 2 { //响应
										conn.respStream.Add(event.Meta.Ts, event.Meta.Seq, int8ArrayToByteNoCopy(event.Msg[:event.BufSize])) //buffers.Write(int8ArrayToByteNoCopy(evtData.Msg[:evtData.BufSize]))
									}
									parser := network.HttpParser{}
									requests := parser.ParseRequest(conn.reqStream)
									response := parser.ParseResponse(conn.respStream)
									conn.requests = append(conn.requests, requests...)
									conn.response = append(conn.response, response...)
									records := conn.match()
									for _, rec := range records {
										fmt.Println(rec.req.URI, string(rec.resp.Body))
									}
								}
								conn.tempMsgEvt = conn.tempMsgEvt[:0]
							}
						}

					}
				}
			case event := <-p.msgEvt:
				tgidFd := event.Meta.TgidFd
				conn := p.pes.GetConnWithTs(tgidFd, event.Meta.Ts)
				//vlog.Println("msg1", event.Meta.Ts)
				if conn == nil {
					continue
				}
				//vlog.Println("msg", conn.LocalIp.String(), conn.LocalPort, conn.RemoteIp.String(), conn.RemotePort, conn.protocol(), event.Meta.Ts)

				if conn.protocol() == "unset" {
					//把事件缓存起来
					conn.tempMsgEvt = append(conn.tempMsgEvt, event)
					continue
				}
				if conn.protocol() != "http" {
					continue
				}
				if len(event.Msg[:event.BufSize]) == 0 {
					continue
				}
				if event.Meta.MsgType == 1 { //请求
					conn.reqStream.Add(event.Meta.Ts, event.Meta.Seq, int8ArrayToByteNoCopy(event.Msg[:event.BufSize])) //buffers.Write(int8ArrayToByteNoCopy(evtData.Msg[:evtData.BufSize]))
				} else if event.Meta.MsgType == 2 { //响应
					conn.respStream.Add(event.Meta.Ts, event.Meta.Seq, int8ArrayToByteNoCopy(event.Msg[:event.BufSize])) //buffers.Write(int8ArrayToByteNoCopy(evtData.Msg[:evtData.BufSize]))
				}
				parser := network.HttpParser{}
				requests := parser.ParseRequest(conn.reqStream)
				response := parser.ParseResponse(conn.respStream)
				conn.requests = append(conn.requests, requests...)
				conn.response = append(conn.response, response...)
				records := conn.match()
				for _, rec := range records {
					fmt.Println(rec.req.URI, string(rec.resp.Body))
				}
			}
		}
	}()
}

// processSocket processes 100 packets from socket.
// Check for each packet if it contains http method.
// If true, print the status line.
func processSocket(sockFD int) {
	vlog.Println("start printing payload for packets with port 80:")

	buf := make([]byte, 65536)
	const macHdrLen = 14

	for i := 0; i < 100; i++ {
		n, _, err := syscall.Recvfrom(sockFD, buf, 0)
		if err != nil {
			continue
		}

		layer2 := buf[macHdrLen:n]
		// minimum ip header length is 20B
		if len(layer2) < 20 {
			continue
		}

		srcIPBytes := layer2[12:16]
		dstIPBytes := layer2[16:20]

		ipTotalLen := int(layer2[2])<<8 + int(layer2[3])
		ipHdrLen := int(layer2[0]&0xf) << 2
		layer3 := layer2[ipHdrLen:]

		// minimum tcp header length is 20B
		if len(layer3) < 20 {
			continue
		}

		srcPortBytes := layer3[0:2]
		DstPortBytes := layer3[2:4]
		tcpHdrLen := int(layer3[12]&0xf0) >> 2

		payloadLen := ipTotalLen - (tcpHdrLen + ipHdrLen)
		if payloadLen <= 0 {
			continue
		}

		payload := string(layer3[tcpHdrLen:])

		if !httpMethod(payload) {
			continue
		}

		index := strings.Index(payload, "\r\n")
		if index != -1 {
			payload = payload[:index]
		}

		vlog.Printf("    %s:%d -> %s:%d    %s\n",
			ipString(srcIPBytes), portInt(srcPortBytes), ipString(dstIPBytes), portInt(DstPortBytes), payload)
	}

	vlog.Println("packet capture stopped")
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func ipString(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func portInt(port []byte) int {
	return int(port[0])<<8 + int(port[1])
}

func httpMethod(payload string) bool {
	// http requires 8B minimum length
	if len(payload) < 8 {
		return false
	}
	if payload[:3] == "GET" {
		return true
	}
	if payload[:4] == "POST" {
		return true
	}
	if payload[:4] == "HTTP" {
		return true
	}

	// More methods like "PUT" can be added here
	return false
}
