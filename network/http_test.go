package network

import (
	"fmt"
	"testing"
)

func Test_ParseRequest(t *testing.T) {
	data1 := []byte("yuiPOST /hhhrrr HTTP/1.1\r\nuser-agent: vscode-restclient\r\naccept-encoding: gzip, deflate\r\nHost: 172.25.183.163:8080")
	stream := &StreamBuffer{}
	stream.Add(123, 1, data1)
	data2 := []byte("\r\nConnection: close\r\nContent-Length: 13\r\n\r\n123456789\r\n\r\n")
	stream.Add(459, uint32(len(data1))+1, data2)
	//data3 := []byte("POST /ooo HTTP/1.1\r\nuser-agent: vscode-restclient\r\naccept-encoding: gzip, deflate\r\nHost: 172.25.183.163:8080\r\nConnection: close\r\nContent-Length: 9\r\n\r\n123456789\r\n\r\n")
	//stream.Add(789, uint32(len(data1)+len(data2)+len(data3)), data3)
	parser := HttpParser{}
	requests := parser.ParseRequest(stream)
	for _, req := range requests {
		fmt.Println(req)
		fmt.Println(string(req.Body))
	}
	fmt.Println("====================================")
	data3 := []byte("yuiPOST /xxx HTTP/1.1\r\nuser-agent: vscode-restclient\r\naccept-encoding: gzip, deflate\r\nHost: 172.25.183.163:8080\r\nConnection: close\r\nContent-Length: 13\r\n\r\n123456789\r\n\r\n")
	stream.Add(963, uint32(len(data1))+uint32(len(data2))+1, data3)
	requests = parser.ParseRequest(stream)
	for _, req := range requests {
		fmt.Println(req)
		fmt.Println(string(req.Body))
	}
}

func Test_ParseResponse(t *testing.T) {
	data1 := []byte("HTTP/1.1 200 OK\r\nDate: Fri, 27 Dec 2024 10:31:48 GMT\r\nContent-Length: 36\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nHello, World! You requested: /hh\r\n\r\n")
	stream := &StreamBuffer{}
	stream.Add(123, uint32(len(data1)), data1)
	parser := HttpParser{}
	res := parser.ParseResponse(stream)
	//fmt.Println(endPos)
	for _, req := range res {
		fmt.Println(req)
		fmt.Println(string(req.Body))
	}
}
