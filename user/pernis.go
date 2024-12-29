package user

import "sync"

type pernis struct {
	connMap *sync.Map
}

func NewPernis() *pernis {
	return &pernis{
		connMap: &sync.Map{},
	}
}

func (p *pernis) GetConn(tgidFd uint64) *Connection {
	if conn, ok := p.connMap.Load(tgidFd); ok {
		return conn.(*Connection)
	} else {
		return nil
	}
}

func (p *pernis) AddConn(tgidFd uint64, conn *Connection) {
	if _, loaded := p.connMap.Load(tgidFd); !loaded { // 检查是否存在
		p.connMap.Store(tgidFd, conn) // 如果不存在，则插入
	}
}

func (p *pernis) DelConn(tgidFd uint64) {
	p.connMap.Delete(tgidFd)
}
