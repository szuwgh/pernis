package user

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"
	//"github.com/cilium/ebpf/rlimit"
	//"github.com/szuwgh/pernis/common/bpf"
	"github.com/szuwgh/pernis/common/inet"
	"github.com/szuwgh/pernis/common/vlog"
	"github.com/vishvananda/netlink"
	//"golang.org/x/sys/unix"
)

// 1:   root qdisc
// |
// 1:1    child class
// /  |  \
// /   |   \
// /    |    \
// /    |    \
// 1:10  1:11  1:12   child classes
// |      |     |
// |     11:    |    leaf class
// |            |
// 10:         12:   qdisc
// /   \       /   \
// 10:1  10:2   12:1  12:2   leaf classes

// qdisc（Queueing Discipline）排队规则，管理设备队列的算法。
// class 可以简单的理解为对要限速的流量进行分类，比如我们将不同的进程进行分类，分成不同的 class，然后每个 class 里面配置对应的限速策略
// filter 过滤器，分类过程可以通过过滤器（filter）完成。过滤器包含许多的判 断条件，匹配到条件之后就算 filter 匹配成功了。
// handle，每个 qdisc 和 class 都会分配一个相应的 handle（句柄），可以指定 handle 对 qdisc 进行配置。有了 handle 我们可以将 qdisc、
// class 组成一个树形的结构。每个 handle 由两部分组成，:，major，minor取值范围是0-65535，书写规范上协作16进制。按照惯例，root qdisc 的 handle 为 1:，这是 1:0 的简写，
// 每个 qdisc 的 minor number 永远是 0。

//ctx context.Context, ifName, objPath string

const (
	DirUnspec  = "unspecified"
	DirIngress = "ingress"
	DirEgress  = "egress"

	BpfFsPath = "/sys/fs/bpf/"

	TC_DADDR_MAP = "tc_daddr_map"
)

const TC_DADDR_MAP_PATH = BpfFsPath + TC_DADDR_MAP

func DirectionToParent(dir string) uint32 {
	switch dir {
	case DirIngress:
		return netlink.HANDLE_MIN_INGRESS
	case DirEgress:
		return netlink.HANDLE_MIN_EGRESS
	}
	return 0

}

// 	link, err := netlink.LinkByName(ifName)
// 	if err != nil {
// 		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
// 	}

// 	qdisc := &netlink.GenericQdisc{
// 		QdiscAttrs: netlink.QdiscAttrs{
// 			LinkIndex: link.Attrs().Index,
// 			Handle:    netlink.MakeHandle(1, 0),
// 			Parent:    netlink.HANDLE_ROOT,
// 		},
// 		QdiscType: "clsact",
// 	}

// 	err = netlink.QdiscReplace(qdisc)
// 	if err != nil {
// 		return fmt.Errorf("could not get replace qdisc: %w", err)
// 	}

// 	//netlink.GenericClass

// 	objs := bpfObjects{}
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		vlog.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// 	filter1 := &netlink.BpfFilter{
// 		FilterAttrs: netlink.FilterAttrs{
// 			LinkIndex: link.Attrs().Index,
// 			Parent:    netlink.HANDLE_MIN_EGRESS,
// 			Handle:    1,
// 			Protocol:  unix.ETH_P_ALL,
// 			Priority:  0,
// 		},
// 		Fd:           objs.TcIngress.FD(),
// 		Name:         objs.TcIngress.String(),
// 		DirectAction: true,
// 	}

// 	if err := netlink.FilterReplace(filter1); err != nil {
// 		return fmt.Errorf("replacing tc filter: %w", err)
// 	}

// 	return nil
// }

// tc qdisc add dev ens33 root handle 10: htb default 12  #在网卡eth0上添加队列规则htb(分层令牌桶),其主序列号为10:,default 12表示当某个ip流不满足任何已设定的filter规则时，将自动归入class 12 中

// tc class add dev ens33 parent 10: classid 10:1 htb rate 100kbit ceil 1000kbit burst 100k   #在队列规则下添加类型,以便有更深入的qdisc,这里所添加的类仍为htb,rate是一个类保证得到的带宽值,ceil是该类能最大能得到的带宽值,burst是令牌桶的大小

// tc filter add dev ens33 protocol ip parent 10:0 prio 1 u32 match ip dst 172.18.5.21/32 match ip dport 5201 0xffff flowid 10:1#添加过滤器,

// 满足后面的筛选条件进入到类10:1中.其中,prio代表优先级,u32是选择器,后面的是服务器的ip地址和端口.
//  0xffff是defmap字段值,数据包的优先权位与defmap字段的值进行"或"运算来决定是否存在这样的匹配,如果是0xffff代表匹配所有包,0则代表不匹配

// tc qdisc del dev ens33 root

// tc -s qdisc  ls dev ens33
// tc -s class  ls dev ens33
// tc -s filter ls dev ens33

// qdisc htb 10: root refcnt 2 r2q 10 default 0x12 direct_packets_stat 189 direct_qlen 1000
//  Sent 42200 bytes 196 pkt (dropped 0, overlimits 0 requeues 0)
//  backlog 0b 0p requeues 0

//  class htb 10:1 root prio 0 rate 100Kbit ceil 1Mbit burst 100Kb cburst 1600b
//  Sent 54 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)
//  backlog 0b 0p requeues 0
//  lended: 1 borrowed: 0 giants: 0
//  tokens: 127932500 ctokens: 193250

//  filter parent 10: protocol ip pref 1 u32 chain 0
// filter parent 10: protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1
// filter parent 10: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 10:1 not_in_hw
//   match ac120515/ffffffff at 16
//   match 00001451/0000ffff at 20

func Add_ip(ip string) (err error) {

	return nil
}

func InitTcQdisc(ifName string) (err error) {
	// 创建一个 netlink socket
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	// 创建一个 qdisc
	qdisc := netlink.NewHtb(netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0x10, 0x0),
		Parent:    netlink.HANDLE_ROOT,
	})
	qdisc.Defcls = 12
	err = netlink.QdiscAdd(qdisc)
	if err != nil {
		vlog.Println("Failed to create qdisc:", err)
		return err
	}
	return
}

type TcClassConfig struct {
	IfName string
	Qdisc  uint32
	Rate   string
	Index  uint16
}

func AddTcClass(config TcClassConfig) (err error) {
	rate, err := inet.BytesPerSecond2Int(config.Rate)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(config.IfName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", config.IfName, err)
	}
	// 创建一个 netlink socket
	class := netlink.NewHtbClass(netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0x10, config.Index),
		Parent:    config.Qdisc,
	}, netlink.HtbClassAttrs{
		Rate: rate, // 100 kB/s
		Ceil: rate,
	})

	err = netlink.ClassAdd(class)
	if err != nil {
		return fmt.Errorf("failed to create class: %s", err)
	}
	return
}

func DeleteIp(ip string) (err error) {
	// 使用bpf.OpenMap打开eBPF map
	m, err := ebpf.LoadPinnedMap(TC_DADDR_MAP_PATH, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open BPF map: %v\n", err)
		return err
	}
	defer m.Close()
	var i = inet.Ip2Int32(net.ParseIP(ip))
	err = m.Delete(&i)
	if err != nil {
		return err
	}

	return nil
}

func SearchClass(class uint32, classList []netlink.Class) netlink.Class {
	i := sort.Search(len(classList), func(i int) bool {
		if classList[i].Attrs().Handle == class {
			return true
		}
		return false
	})
	return classList[i]
}

func LsIp() (err error) {
	// link, err := netlink.LinkByName(ifName)
	// if err != nil {
	// 	return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	// }
	m, err := ebpf.LoadPinnedMap(TC_DADDR_MAP_PATH, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open BPF map: %v\n", err)
		return err
	}
	// classList, err := netlink.ClassList(link, qdisc)
	// if err != nil {
	// 	return fmt.Errorf("failed to get class: %s", err)
	// }
	iter := m.Iterate()
	var ip uint32
	var class uint32

	for iter.Next(&ip, &class) {
		//class := sort.Search(class, f func(int) bool)

		// vlog.Printf("ip :%s class:%s(%d) rate:%s\n",
		// 	intToIP(ip),
		// 	class,
		// 	netlink.HandleStr(v.Attrs().Handle),
		// 	v.Attrs().Handle,
		// 	v.Type())
		vlog.Println(intToIP(ip), class)
	}
	return nil
}

func AddIp(ip string, class uint32) (err error) {

	// 使用bpf.OpenMap打开eBPF map
	m, err := ebpf.LoadPinnedMap(TC_DADDR_MAP_PATH, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open BPF map: %v\n", err)
		return err
	}
	defer m.Close()
	var i = inet.Ip2Int32(net.ParseIP(ip))
	err = m.Put(&i, &class)
	if err != nil {
		return err
	}

	return nil
}

func LsTcClass(ifName string, qdisc uint32) (err error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}
	classList, err := netlink.ClassList(link, qdisc)
	if err != nil {
		return fmt.Errorf("failed to get class: %s", err)
	}
	for _, v := range classList {
		link, err := netlink.LinkByIndex(v.Attrs().LinkIndex)
		if err != nil {
			return fmt.Errorf("getting interface %s by name: %w", ifName, err)
		}
		switch v.Type() {
		case "htb":
			{
				htbClass, ok := v.(*netlink.HtbClass)
				if !ok {
					continue
				}
				vlog.Printf("class link index:%s(%d) parent:%s  handle:%s(%d) type:%s rate:%s\n",
					link.Attrs().Name,
					v.Attrs().LinkIndex,
					netlink.HandleStr(v.Attrs().Parent),
					netlink.HandleStr(v.Attrs().Handle), v.Attrs().Handle,
					v.Type(),
					inet.IntToToBytesPerSecond(htbClass.Rate*8))
			}
		}

	}
	return
}

func LsTcQdisc(ifName string) (err error) {
	// 创建一个 netlink socket
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	qdiscList, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("getting Qdisc %s by name: %w", ifName, err)
	}
	for _, v := range qdiscList {
		link, err := netlink.LinkByIndex(v.Attrs().LinkIndex)
		if err != nil {
			return fmt.Errorf("getting interface %s by name: %w", ifName, err)
		}
		vlog.Printf("qdisc link index:%s(%d) handle:%s(%d) type:%s\n", link.Attrs().Name, v.Attrs().LinkIndex, netlink.HandleStr(v.Attrs().Handle), v.Attrs().Handle, v.Type())
	}
	return
}

func LsTcBpf(ifName string, qdisc uint32) (err error) {
	// 创建一个 netlink socket
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	filterList, err := netlink.FilterList(link, qdisc)
	if err != nil {
		return fmt.Errorf("getting Qdisc %s by name: %w", ifName, err)
	}
	for _, v := range filterList {
		link, err := netlink.LinkByIndex(v.Attrs().LinkIndex)
		if err != nil {
			return fmt.Errorf("getting interface %s by name: %w", ifName, err)
		}
		vlog.Printf("filter link index:%s(%d) handle:%s(%d) type:%s\n", link.Attrs().Name, v.Attrs().LinkIndex, netlink.HandleStr(v.Attrs().Handle), v.Attrs().Handle, v.Type())
	}
	return
}

func RmTcQdisc(ifName string, handle uint32) (err error) {
	// 创建一个 netlink socket
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	qdiscList, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}

	for _, f := range qdiscList {
		if f.Attrs().Handle == handle {
			continue
		}
		if err := netlink.QdiscDel(f); err != nil {
			return err
		}
	}
	return
}

// func DeleteEbpfTc(ifName string, qdisc uint32) (err error) {
// 	// 创建一个 netlink socket
// 	link, err := netlink.LinkByName(ifName)
// 	if err != nil {
// 		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
// 	}
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		vlog.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()
// 	mapInfo, err := objs.TcDaddrMap.Info()
// 	if err != nil {
// 		return err
// 	}
// 	mapPath := BpfFsPath + mapInfo.Name
// 	err = bpf.UnMapPinned(mapPath)
// 	if err != nil {
// 		return err
// 	}
// 	filter := &netlink.BpfFilter{
// 		FilterAttrs: netlink.FilterAttrs{
// 			LinkIndex: link.Attrs().Index,
// 			Parent:    qdisc,
// 			Protocol:  unix.ETH_P_IP,
// 			Priority:  1,
// 		},
// 		Fd:           objs.TcEgress.FD(),
// 		Name:         objs.TcEgress.String(),
// 		DirectAction: false,
// 	}

// 	err = netlink.FilterDel(filter)
// 	if err != nil {
// 		vlog.Println("Failed to del filter:", err)
// 		return
// 	}

// 	return nil
// }

func DeleteTcClass(ifName string, qdisc uint32, handle uint32) (err error) {
	// 创建一个 netlink socket
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	// 删除一个class
	class := netlink.NewHtbClass(netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    handle,
		Parent:    qdisc,
	}, netlink.HtbClassAttrs{})

	err = netlink.ClassDel(class)
	if err != nil {
		vlog.Println("Failed to del class:", err)
		return
	}

	return nil
}

// func AttachEbpfTc(ifName string, qdisc uint32) (err error) {
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		vlog.Fatal(err)
// 	}
// 	// 创建一个 netlink socket
// 	link, err := netlink.LinkByName(ifName)
// 	if err != nil {
// 		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
// 	}
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		vlog.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// 	if !bpf.IsMapPinned(TC_DADDR_MAP_PATH) {
// 		err = objs.TcDaddrMap.Pin(TC_DADDR_MAP_PATH)
// 		if err != nil {
// 			return fmt.Errorf("failed to pin map %s", err)
// 		}
// 	} else {
// 		return fmt.Errorf("failed to attach bpf map have to pin, try removing ebpf and then attach ebpf")
// 	}

// 	filter := &netlink.BpfFilter{
// 		FilterAttrs: netlink.FilterAttrs{
// 			LinkIndex: link.Attrs().Index,
// 			Parent:    qdisc,
// 			Protocol:  unix.ETH_P_IP,
// 			Priority:  1,
// 		},
// 		Fd:           objs.TcEgress.FD(),
// 		Name:         objs.TcEgress.String(),
// 		DirectAction: false,
// 	}

// 	err = netlink.FilterReplace(filter)
// 	if err != nil {
// 		vlog.Println("Failed to add filter:", err)
// 		return
// 	}

// 	return nil
// }

func ObserveTC(ifName string) (err error) {

	// 创建一个 netlink socket
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	// 创建一个 qdisc

	qdisc := netlink.NewHtb(netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0x10, 0x0),
		Parent:    netlink.HANDLE_ROOT,
	})
	qdisc.Defcls = 12

	err = netlink.QdiscAdd(qdisc)
	if err != nil {
		vlog.Println("Failed to create qdisc:", err)
		return err
	}

	class := netlink.NewHtbClass(netlink.ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0x10, 0x1),
		Parent:    qdisc.QdiscAttrs.Handle,
	}, netlink.HtbClassAttrs{
		Rate: 100 * 1000, //5M
		Ceil: 100 * 1000,
	})

	err = netlink.ClassAdd(class)
	if err != nil {
		vlog.Println("Failed to create class:", err)
		return err
	}
	vlog.Printf("%x\n", class.Handle)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		vlog.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 使用 u32 创建过滤器
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdisc.QdiscAttrs.Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_IP,
		},
		ClassId: class.Handle,
		Sel: &netlink.TcU32Sel{
			Keys: []netlink.TcU32Key{
				{
					Mask: 0xffffffff,
					Val:  binary.BigEndian.Uint32(net.ParseIP("172.18.5.21").To4()),
					Off:  16,
				},
				{
					Mask: 0xffff,
					Val:  5201,
					Off:  20,
				},
			},
		},
	}
	filter.Sel.Flags |= netlink.TC_U32_TERMINAL
	err = netlink.FilterReplace(filter)
	if err != nil {
		vlog.Println("Failed to add filter:", err)
		return
	}

	return nil
}

func ListFilters(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	qdiscList, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}

	vlog.Println(qdiscList)
	vlog.Println("-----")

	classList, err := netlink.ClassList(link, netlink.MakeHandle(0x1, 0x0))
	if err != nil {
		return err
	}
	vlog.Println(classList)
	vlog.Println("-----")

	filters, err := netlink.FilterList(link, netlink.MakeHandle(0x1, 0x5))
	if err != nil {
		return err
	}
	vlog.Println("------------")
	vlog.Println(filters)

	return nil
}

func RemoveTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	qdiscList, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}

	vlog.Println(qdiscList)
	for _, f := range qdiscList {
		if f.Attrs().Handle != netlink.MakeHandle(0x10, 0x0) || f.Attrs().Handle != netlink.MakeHandle(0x11, 0x1) {
			continue
		}
		if err := netlink.QdiscDel(f); err != nil {
			return err
		}
	}

	return nil
}
