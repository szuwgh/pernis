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

func (p *pernis) GetConnWithTs(tgidFd uint64, ts uint64) *Connection {
	conn := p.GetConn(tgidFd)
	if conn != nil {
		// 连接没有关闭
		if !conn.isClose {
			if conn.closeTime == 0 {
				return conn
			}
			// 关闭时间大于事件时间
			if conn.closeTime > 0 && conn.closeTime > ts {
				return conn
			}
		}
		//寻找后面的连接
		for _, c := range conn.chainConn {
			if !c.isClose {
				if c.closeTime == 0 {
					return c
				}
				// 关闭时间大于事件时间
				if c.closeTime > 0 && c.closeTime > ts {
					return c
				}
			}
		}
	}
	return nil
}

func (p *pernis) AddConn(tgidFd uint64, conn *Connection) {
	existedConn := p.GetConn(tgidFd)
	if existedConn != nil {
		if !existedConn.IsSameConn(conn) {
			existedConn.chainConn = append(existedConn.chainConn, conn)
		}
	} else {
		p.connMap.Store(tgidFd, conn) // 如果不存在，则插入
	}
	// if _, loaded := p.connMap.Load(tgidFd); !loaded { // 检查是否存在
	// 	p.connMap.Store(tgidFd, conn) // 如果不存在，则插入
	// }
}

func (p *pernis) DelConn(tgidFd uint64) {
	p.connMap.Delete(tgidFd)
}
