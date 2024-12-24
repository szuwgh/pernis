package byteorder

import (
	"bytes"
	"encoding/binary"
)

type AnyInt interface {
	int8 | int16 | int32 | int64 | uint8 | uint16 | uint32 | uint64
}

func IntToBytes[I AnyInt](n I) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, n)
	return buf.Bytes()
}
