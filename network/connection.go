package network

import (
	"github.com/szuwgh/pernis/common/byteorder"
	"net"
)

type IpAddr struct {
	addr []byte
	ip   uint32
}

func ToIpAddr(ip uint32) IpAddr {
	return IpAddr{
		addr: byteorder.IntToBytes(ip),
		ip:   ip,
	}
}

func (a *IpAddr) String() string {
	if len(a.addr) == 4 {
		return net.IP(a.addr).To4().String()
	} else if len(a.addr) == 8 {
		return net.IP(a.addr).To16().String()
	} else {
		panic("unknown addr type")
	}
}

func (a *IpAddr) Ip() uint32 {
	return a.ip
}

type Port uint16
