package network

import (
	//"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

var HTTP_REQ_PATTERN = [][]byte{[]byte("GET "), []byte("HEAD "), []byte("POST "), []byte("PUT "), []byte("DELETE "), []byte("CONNECT "), []byte("OPTIONS "), []byte("TRACE "), []byte("PATCH ")}
var HTTP_RESP_PATTERN = [][]byte{[]byte("HTTP/1.1 "), []byte("HTTP/1.0 ")}

var HTTP_HEADER_BOUNDARY = []byte("\r\n\r\n") // http 请求头分隔符

const EOF = -1

type GrabHttpRequest struct {
	Host     string
	Method   string
	URI      string
	Version  string
	Headers  map[string]string
	Body     []byte
	ts       uint64
	byteSize int
}

func (r *GrabHttpRequest) Timestamp() uint64 {
	return r.ts
}

type GrabHttpResponse struct {
	Method     string
	httpStatus string
	statusMsg  string
	Headers    map[string]string
	Body       []byte
	ts         uint64
	byteSize   int
}

func (r *GrabHttpResponse) Timestamp() uint64 {
	return r.ts
}

type StreamEvent struct {
	ts  uint64
	seq uint32
}

type StreamBuffer struct {
	events   []StreamEvent
	buffers  bytes.Buffer
	prevRead uint32
}

func (s *StreamBuffer) find(seq uint32) *StreamEvent {
	for i := len(s.events) - 1; i >= 0; i-- {
		if seq >= s.events[i].seq-s.prevRead {
			return &s.events[i]
		}
	}
	return nil
}

func (s *StreamBuffer) Add(ts uint64, seq uint32, buf []byte) {
	s.events = append(s.events, StreamEvent{ts, seq})
	s.buffers.Write(buf)
}

type PayloadMessage struct {
	data []byte
}

// POST /hhhrrr HTTP/1.1
// user-agent: vscode-restclient
// accept-encoding: gzip, deflate
// Host: 172.25.183.163:8080
// Connection: close
// Content-Length: 0

func (p *PayloadMessage) ReadUntilBlankWithLength(from int, fixedLength int) (int, []byte) {
	var length = len(p.data)
	if fixedLength+from < length {
		length = from + fixedLength
	}
	for i := from; i < length; i++ {
		if p.data[i] == ' ' {
			return i + 1, p.data[from:i]
		}
	}
	return length, p.data[from:length]
}

func (p *PayloadMessage) ReadUntilCRLF(from int) (offset int, data []byte) {
	var length = len(p.data)
	if from >= length {
		return EOF, nil
	}

	for i := from; i < length; i++ {
		if p.data[i] != '\r' {
			continue
		}

		if i == length-1 {
			// End with \r
			offset = length
			data = p.data[from : length-1]
			return
		} else if p.data[i+1] == '\n' {
			// \r\n
			offset = i + 2
			data = p.data[from:i]
			return
		} else {
			return EOF, nil
		}
	}

	offset = length
	data = p.data[from:]
	return
}

func (p *PayloadMessage) ReadUntilBlank(from int) (int, []byte) {
	var length = len(p.data)

	for i := from; i < length; i++ {
		if p.data[i] == ' ' {
			return i + 1, p.data[from:i]
		}
	}
	return length, p.data[from:length]
}

type HttpParser struct {
}

func (h *HttpParser) ParseRequest(stream *StreamBuffer) (requests []*GrabHttpRequest) {
	data := stream.buffers.Bytes()
	startPos := 0
	endPos := 0
	var err error
	for {
		if len(data) == 0 {
			break
		}
		headerEnd := bytes.Index(data[startPos:], HTTP_HEADER_BOUNDARY)
		if headerEnd == -1 {
			break
		}
		// 提取请求头部
		header := data[:headerEnd]
		prevPos := -1
		for _, pattern := range HTTP_REQ_PATTERN {
			patternIndex := bytes.Index(header, pattern)
			if patternIndex != -1 {
				prevPos = patternIndex
				break
			}
		}
		if prevPos == -1 { //没有匹配http方法
			data = data[headerEnd+len(HTTP_HEADER_BOUNDARY):]
			continue
		}
		start := 0
		httpHeader := header[prevPos:]
		pm := PayloadMessage{data: httpHeader}
		offset, method := pm.ReadUntilBlankWithLength(start, 8)
		offset, url := pm.ReadUntilBlank(offset)
		_, version := pm.ReadUntilBlank(offset)
		_, headers := parseHeaders(&pm)
		contentLength := headers["content-length"]
		length := 0
		if contentLength != "" {
			length, err = strconv.Atoi(contentLength)
			if err != nil {
				continue
			}
		}

		msgBody := data[headerEnd+len(HTTP_HEADER_BOUNDARY):]
		if len(msgBody) < length {
			break
		}
		var body []byte
		if length > 0 {
			// if length > 1024 {
			// 	length = 1024
			// }
			// 提取请求体
			body = msgBody[:length%1024]
		}

		endPos = headerEnd + len(HTTP_HEADER_BOUNDARY) + length
		event := stream.find(uint32(endPos))
		ts := uint64(0)
		if event != nil {
			ts = event.ts
		}
		requests = append(requests, &GrabHttpRequest{
			Method:   string(method),
			URI:      string(url),
			Version:  string(version),
			Headers:  headers,
			Body:     body, //只读取1024 字节
			ts:       ts,
			byteSize: endPos - prevPos,
		})
		data = data[endPos:]
		stream.prevRead = uint32(endPos)
		stream.buffers.Next(endPos)
	}

	return
}

// HTTP/1.1 200 OK
// Date: Fri, 27 Dec 2024 10:31:48 GMT
// Content-Length: 36
// Content-Type: text/plain; charset=utf-8
// Connection: close

// Hello, World! You requested: /hh

func (h *HttpParser) ParseResponse(stream *StreamBuffer) (requests []*GrabHttpResponse) {
	data := stream.buffers.Bytes()
	startPos := 0
	endPos := 0
	for {
		if len(data) == 0 {
			break
		}
		headerEnd := bytes.Index(data[startPos:], HTTP_HEADER_BOUNDARY)
		if headerEnd == -1 {
			break
		}
		// 提取请求头部
		header := data[:headerEnd]
		prevPos := -1
		for _, pattern := range HTTP_RESP_PATTERN {
			patternIndex := bytes.Index(header, pattern)
			if patternIndex != -1 {
				prevPos = patternIndex
				break
			}
		}
		if prevPos == -1 { //没有匹配http方法
			data = data[headerEnd+len(HTTP_HEADER_BOUNDARY):]
			continue
		}
		start := 0
		httpHeader := header[prevPos:]
		pm := PayloadMessage{data: httpHeader}
		offset, method := pm.ReadUntilBlankWithLength(start, 8)
		offset, httpStatus := pm.ReadUntilBlank(offset)
		_, statusMsg := pm.ReadUntilBlank(offset)
		_, headers := parseHeaders(&pm)
		contentLength := headers["content-length"]
		length, err := strconv.Atoi(contentLength) //length 包含 HTTP_HEADER_BOUNDARY
		if err != nil {
			fmt.Println(err)
			break
		}
		msgBody := data[headerEnd+len(HTTP_HEADER_BOUNDARY):]
		if len(msgBody) < length {
			fmt.Println("msgBody length is not enough")
			break
		}
		var body []byte
		if length > 0 {
			// 提取请求体
			body = msgBody[:length%1024]
		}
		endPos = headerEnd + len(HTTP_HEADER_BOUNDARY) + length
		event := stream.find(uint32(endPos))
		ts := uint64(0)
		if event != nil {
			ts = event.ts
		}
		requests = append(requests, &GrabHttpResponse{
			Method:     string(method),
			httpStatus: string(httpStatus),
			statusMsg:  string(statusMsg),
			Headers:    headers,
			Body:       body, //只读取1024 字节
			ts:         ts,
			byteSize:   endPos - prevPos,
		})
		data = data[endPos:]
		stream.prevRead = uint32(endPos)
		stream.buffers.Next(endPos)
	}

	return
}

func parseHeaders(message *PayloadMessage) (int, map[string]string) {
	header := make(map[string]string)
	offset := 0
	from, data := message.ReadUntilCRLF(0)
	if data == nil {
		return 0, header
	}
	for {
		from, data = message.ReadUntilCRLF(from)
		if data == nil {
			return offset, header
		}
		offset = from
		if position := strings.Index(string(data), ":"); position > 0 && position < len(data)-1 {
			header[strings.ToLower(string(data[0:position]))] = string(data[position+2:])
			continue
		}
		return offset, header
	}
}
