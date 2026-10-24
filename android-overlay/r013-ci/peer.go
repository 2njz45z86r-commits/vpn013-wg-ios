// SPDX-License-Identifier: MIT
// Ephemeral GitHub-hosted Linux responder; no customer keys or OS TUN.
package main
import (
 "crypto/ecdh"
 "crypto/rand"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "fmt"
 "io"
 "net"
 "os"
 "os/signal"
 "path/filepath"
 "strings"
 "sync"
 "syscall"
 "github.com/amnezia-vpn/amneziawg-go/v3/conn"
 "github.com/amnezia-vpn/amneziawg-go/v3/device"
 "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)
type echoDevice struct {
	packets chan []byte
	events  chan tun.Event
	done    chan struct{}
	once    sync.Once
}

func (d *echoDevice) File() *os.File           { return nil }
func (d *echoDevice) MTU() (int, error)        { return 1420, nil }
func (d *echoDevice) Name() (string, error)    { return "memory-only-ci-peer", nil }
func (d *echoDevice) Events() <-chan tun.Event { return d.events }
func (d *echoDevice) BatchSize() int           { return 1 }
func (d *echoDevice) Close() error             { d.once.Do(func() { close(d.done); close(d.events) }); return nil }
func (d *echoDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-d.done:
		return 0, io.EOF
	case packet := <-d.packets:
		if len(bufs) == 0 || offset+len(packet) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}
func checksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) > 1 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func (d *echoDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buffer := range bufs {
		packet := buffer[offset:]
		if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 1 {
			continue
		}
		header := int(packet[0]&15) * 4
		if header < 20 || header+8 > len(packet) || packet[header] != 8 {
			continue
		}
		if !net.IP(packet[16:20]).Equal(net.ParseIP("10.13.99.1")) {
			continue
		}
		reply := append([]byte(nil), packet...)
		copy(reply[12:16], packet[16:20])
		copy(reply[16:20], packet[12:16])
		reply[10], reply[11] = 0, 0
		binary.BigEndian.PutUint16(reply[10:12], checksum(reply[:header]))
		reply[header] = 0
		reply[header+2], reply[header+3] = 0, 0
		binary.BigEndian.PutUint16(reply[header+2:header+4], checksum(reply[header:]))
		select {
		case d.packets <- reply:
		case <-d.done:
			return 0, io.EOF
		}
	}
	return len(bufs), nil
}

func run() error {
 if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Linux" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" { return fmt.Errorf("Disposable authorized CI runner required") }
 clientKey, err := ecdh.X25519().GenerateKey(rand.Reader); if err != nil { return err }
 serverKey, err := ecdh.X25519().GenerateKey(rand.Reader); if err != nil { return err }
 memory := &echoDevice{packets:make(chan []byte,8),events:make(chan tun.Event,1),done:make(chan struct{})}
 peer := device.NewDevice(memory,conn.NewDefaultBind(),device.NewLogger(device.LogLevelSilent,"")); defer peer.Close()
 uapi := "private_key="+hex.EncodeToString(serverKey.Bytes())+"\nlisten_port=0\njc=3\njmin=40\njmax=70\ns1=20\ns2=30\nh1=1001\nh2=1002\nh3=1003\nh4=1004\npublic_key="+hex.EncodeToString(clientKey.PublicKey().Bytes())+"\nallowed_ip=10.13.99.2/32\n"
 if peer.IpcSet(uapi) != nil || peer.Up() != nil { return fmt.Errorf("Synthetic AWG responder did not start") }
 state,err:=peer.IpcGet(); if err != nil { return err }; port:=""
 for _,line:=range strings.Split(state,"\n") { if strings.HasPrefix(line,"listen_port=") { port=strings.TrimPrefix(line,"listen_port=") } }
 if port=="" || port=="0" { return fmt.Errorf("No synthetic UDP port") }
 contents := "[Interface]\nPrivateKey = "+base64.StdEncoding.EncodeToString(clientKey.Bytes())+"\nAddress = 10.13.99.2/32\nDNS = 1.1.1.1\nJc = 3\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\n[Peer]\nPublicKey = "+base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes())+"\nEndpoint = 10.0.2.2:"+port+"\nAllowedIPs = 10.13.99.1/32\nPersistentKeepalive = 1\n"
 path:=filepath.Join(os.Getenv("RUNNER_TEMP"),"r013-synthetic.conf")
 if err=os.WriteFile(path,[]byte(contents),0600);err!=nil{return err};defer os.Remove(path)
 fmt.Println("Ephemeral AWG responder ready; private fixture is outside artifacts")
 done:=make(chan os.Signal,1);signal.Notify(done,syscall.SIGINT,syscall.SIGTERM);<-done;return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
