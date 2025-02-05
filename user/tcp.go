package user

import (
	"encoding/binary"
	"net"
	//"time"
	//"github.com/cilium/ebpf/link"
	//"github.com/szuwgh/pernis/common/vlog"
)

// ebpf可通过跟踪内核函数，统计不同层次的网络流量。各层的流量差异主要在于包头，重传，控制报文等等。

// L4 TCP 纯数据流量：
// 上行：kprobe统计tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) size
//  下行：kprobe统计 tcp_cleanup_rbuf(struct sock *sk, int copied) copied

//  L4 UDP 纯数据流量：
//  上行：kprobe统计 udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) len
//  下行：kprobe统计 skb_consume_udp(struct sock *sk, struct sk_buff *skb, int len) len

//  L3 IP 流量
//  上行： kprobe统计 ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) skb->len
//  下行： kprobe统计 ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) skb->len

//  L2 全部网络包流量：
//  上行：tracepoint统计 net/net_dev_queue args->len
//  下行：tracepoint统计 net/netif_receive_skb args->len

const FN_TCP_SENDMSG = "tcp_sendmsg"
const FN_TCP_CLEANUP_RBUF = "tcp_cleanup_rbuf"

type Ipv4KeyT struct {
	Saddr uint32
	Daddr uint32
}

// func AttachTcpSendMsgKprobe() (err error) {

// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		vlog.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// 	kp, err := link.Kprobe(FN_TCP_SENDMSG, objs.KtcpSendmsg, nil)
// 	if err != nil {
// 		vlog.Fatalf("opening kprobe: %s", err)
// 	}
// 	defer kp.Close()

// 	kp2, err := link.Kprobe(FN_TCP_CLEANUP_RBUF, objs.KtcpCleanupRbuf, nil)
// 	if err != nil {
// 		vlog.Fatalf("opening kprobe: %s", err)
// 	}
// 	defer kp2.Close()

// 	// Read loop reporting the total amount of times the kernel
// 	// function was entered, once per second.
// 	ticker := time.NewTicker(2 * time.Second)
// 	defer ticker.Stop()

// 	vlog.Println("Waiting for events..")
// 	vlog.Printf("%-15s  -> %-15s  %-6s",
// 		"Src addr",
// 		"Dest addr",
// 		"Bytes",
// 	)
// 	for range ticker.C {
// 		var values1 []uint32
// 		var key Ipv4KeyT

// 		var values2 []uint32
// 		// if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
// 		// 	vlog.Fatalf("reading map: %v", err)
// 		// }
// 		iter := objs.bpfMaps.Ipv4SendBytes.Iterate()
// 		for iter.Next(&key, &values1) {
// 			var sum1 uint32
// 			for _, n := range values1 {
// 				sum1 += n
// 			}
// 			saddr := key.Saddr
// 			daddr := key.Daddr
// 			vlog.Printf("%-15s -> %-15s  %-6d",
// 				intToIP(saddr),
// 				intToIP(daddr),
// 				sum1,
// 			)
// 			//key.Saddr = saddr
// 			//key.Daddr = daddr
// 			objs.bpfMaps.Ipv4RecvBytes.Lookup(key, &values2)
// 			var sum2 uint32
// 			for _, n := range values2 {
// 				sum2 += n
// 			}
// 			vlog.Printf("%-15s <- %-15s  %-6d",
// 				intToIP(daddr),
// 				intToIP(saddr),
// 				sum2,
// 			)
// 		}
// 	}
// 	return nil
// }

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}
