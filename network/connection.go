package network

import (
	"net"
)

type IpAddr []byte

func (a *IpAddr) String() string {
	if len(*a) == 4 {
		return net.IP(*a).To4().String()
	} else if len(*a) == 8 {
		return net.IP(*a).To16().String()
	} else {
		panic("unknown addr type")
	}
}

// type Connection struct {
// 	LocalIp  IpAddr
// 	RemoteIp IpAddr
// }
