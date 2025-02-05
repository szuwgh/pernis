// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package user

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSsl102a returns the embedded CollectionSpec for ssl102a.
func loadSsl102a() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Ssl102aBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load ssl102a: %w", err)
	}

	return spec, err
}

// loadSsl102aObjects loads ssl102a and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*ssl102aObjects
//	*ssl102aPrograms
//	*ssl102aMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSsl102aObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSsl102a()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// ssl102aSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ssl102aSpecs struct {
	ssl102aProgramSpecs
	ssl102aMapSpecs
}

// ssl102aSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ssl102aProgramSpecs struct {
	UprobeSSL_read    *ebpf.ProgramSpec `ebpf:"uprobe_SSL_read"`
	UprobeSsL_write   *ebpf.ProgramSpec `ebpf:"uprobe_ssL_write"`
	UretprobeSSL_read *ebpf.ProgramSpec `ebpf:"uretprobe_SSL_read"`
	UretprobeSslWrite *ebpf.ProgramSpec `ebpf:"uretprobe_ssl_write"`
}

// ssl102aMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ssl102aMapSpecs struct {
	ActiveSslReadArgsMap  *ebpf.MapSpec `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.MapSpec `ebpf:"active_ssl_write_args_map"`
	DataBufferHeap        *ebpf.MapSpec `ebpf:"data_buffer_heap"`
	SslUserSpaceCallMap   *ebpf.MapSpec `ebpf:"ssl_user_space_call_map"`
	TlsEvents             *ebpf.MapSpec `ebpf:"tls_events"`
}

// ssl102aObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSsl102aObjects or ebpf.CollectionSpec.LoadAndAssign.
type ssl102aObjects struct {
	ssl102aPrograms
	ssl102aMaps
}

func (o *ssl102aObjects) Close() error {
	return _Ssl102aClose(
		&o.ssl102aPrograms,
		&o.ssl102aMaps,
	)
}

// ssl102aMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSsl102aObjects or ebpf.CollectionSpec.LoadAndAssign.
type ssl102aMaps struct {
	ActiveSslReadArgsMap  *ebpf.Map `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.Map `ebpf:"active_ssl_write_args_map"`
	DataBufferHeap        *ebpf.Map `ebpf:"data_buffer_heap"`
	SslUserSpaceCallMap   *ebpf.Map `ebpf:"ssl_user_space_call_map"`
	TlsEvents             *ebpf.Map `ebpf:"tls_events"`
}

func (m *ssl102aMaps) Close() error {
	return _Ssl102aClose(
		m.ActiveSslReadArgsMap,
		m.ActiveSslWriteArgsMap,
		m.DataBufferHeap,
		m.SslUserSpaceCallMap,
		m.TlsEvents,
	)
}

// ssl102aPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSsl102aObjects or ebpf.CollectionSpec.LoadAndAssign.
type ssl102aPrograms struct {
	UprobeSSL_read    *ebpf.Program `ebpf:"uprobe_SSL_read"`
	UprobeSsL_write   *ebpf.Program `ebpf:"uprobe_ssL_write"`
	UretprobeSSL_read *ebpf.Program `ebpf:"uretprobe_SSL_read"`
	UretprobeSslWrite *ebpf.Program `ebpf:"uretprobe_ssl_write"`
}

func (p *ssl102aPrograms) Close() error {
	return _Ssl102aClose(
		p.UprobeSSL_read,
		p.UprobeSsL_write,
		p.UretprobeSSL_read,
		p.UretprobeSslWrite,
	)
}

func _Ssl102aClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed ssl102a_bpfel_x86.o
var _Ssl102aBytes []byte
