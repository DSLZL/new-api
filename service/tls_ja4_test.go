package service

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeConn struct{ addr net.Addr }

func (f *fakeConn) Read(_ []byte) (n int, err error)         { return 0, nil }
func (f *fakeConn) Write(_ []byte) (n int, err error)        { return 0, nil }
func (f *fakeConn) Close() error                             { return nil }
func (f *fakeConn) LocalAddr() net.Addr                      { return &net.TCPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr                     { return f.addr }
func (f *fakeConn) SetDeadline(_ time.Time) error            { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error        { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error       { return nil }

func TestTLSJA4Cache_ReusesSameConnectionValueWithinTTL(t *testing.T) {
	addr := "198.51.100.10:44321"
	tlsJA4Store.Delete(addr)

	hello := &tls.ClientHelloInfo{
		ServerName:         "example.com",
		CipherSuites:       []uint16{0x1301, 0x1302},
		SupportedVersions:  []uint16{0x0304},
		Conn:               &fakeConn{addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 44321}},
	}
	CaptureTLSJA4FromClientHello(hello)

	first := GetTLSJA4FromRemoteAddr(addr)
	second := GetTLSJA4FromRemoteAddr(addr)
	require.NotEmpty(t, first)
	require.Equal(t, first, second)
}

func TestTLSJA4Cache_ExpiresEntry(t *testing.T) {
	addr := "203.0.113.15:54231"
	tlsJA4Store.Store(addr, tlsJA4CacheEntry{
		value:     "ja4c_expire_me",
		expiresAt: time.Now().Add(-time.Second),
	})

	got := GetTLSJA4FromRemoteAddr(addr)
	require.Equal(t, "", got)

	_, exists := tlsJA4Store.Load(addr)
	require.False(t, exists)
}
