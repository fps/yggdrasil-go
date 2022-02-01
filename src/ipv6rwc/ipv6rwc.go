package ipv6rwc

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"strings"
	// "encoding/hex"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

    // "github.com/google/gopacket"
    // "github.com/google/gopacket/layers"
	// "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"

	iwt "github.com/Arceliar/ironwood/types"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const keyStoreTimeout = 2 * time.Minute

// Out-of-band packet types
const (
	typeKeyDummy = iota // nolint:deadcode,varcheck
	typeKeyLookup
	typeKeyResponse
)

type keyArray [ed25519.PublicKeySize]byte

type keyStore struct {
	core         *core.Core
	address      address.Address
	subnet       address.Subnet
	mutex        sync.Mutex
	keyToInfo    map[keyArray]*keyInfo
	addrToInfo   map[address.Address]*keyInfo
	addrBuffer   map[address.Address]*buffer
	subnetToInfo map[address.Subnet]*keyInfo
	subnetBuffer map[address.Subnet]*buffer
	mtu          uint64
}

type keyInfo struct {
	key     keyArray
	address address.Address
	subnet  address.Subnet
	timeout *time.Timer // From calling a time.AfterFunc to do cleanup
}

type buffer struct {
	packet  []byte
	timeout *time.Timer
}

func (k *keyStore) init(c *core.Core) {
	k.core = c
	k.address = *address.AddrForKey(k.core.PublicKey())
	k.subnet = *address.SubnetForKey(k.core.PublicKey())
	if err := k.core.SetOutOfBandHandler(k.oobHandler); err != nil {
		err = fmt.Errorf("tun.core.SetOutOfBandHander: %w", err)
		panic(err)
	}
	k.keyToInfo = make(map[keyArray]*keyInfo)
	k.addrToInfo = make(map[address.Address]*keyInfo)
	k.addrBuffer = make(map[address.Address]*buffer)
	k.subnetToInfo = make(map[address.Subnet]*keyInfo)
	k.subnetBuffer = make(map[address.Subnet]*buffer)
	k.mtu = 1280 // Default to something safe, expect user to set this
}

func (k *keyStore) sendToAddress(addr address.Address, bs []byte) {
	k.mutex.Lock()
	if info := k.addrToInfo[addr]; info != nil {
		k.resetTimeout(info)
		k.mutex.Unlock()
		_, _ = k.core.WriteTo(bs, iwt.Addr(info.key[:]))
	} else {
		var buf *buffer
		if buf = k.addrBuffer[addr]; buf == nil {
			buf = new(buffer)
			k.addrBuffer[addr] = buf
		}
		msg := append([]byte(nil), bs...)
		buf.packet = msg
		if buf.timeout != nil {
			buf.timeout.Stop()
		}
		buf.timeout = time.AfterFunc(keyStoreTimeout, func() {
			k.mutex.Lock()
			defer k.mutex.Unlock()
			if nbuf := k.addrBuffer[addr]; nbuf == buf {
				delete(k.addrBuffer, addr)
			}
		})
		k.mutex.Unlock()
		k.sendKeyLookup(addr.GetKey())
	}
}

func (k *keyStore) sendToSubnet(subnet address.Subnet, bs []byte) {
	k.mutex.Lock()
	if info := k.subnetToInfo[subnet]; info != nil {
		k.resetTimeout(info)
		k.mutex.Unlock()
		_, _ = k.core.WriteTo(bs, iwt.Addr(info.key[:]))
	} else {
		var buf *buffer
		if buf = k.subnetBuffer[subnet]; buf == nil {
			buf = new(buffer)
			k.subnetBuffer[subnet] = buf
		}
		msg := append([]byte(nil), bs...)
		buf.packet = msg
		if buf.timeout != nil {
			buf.timeout.Stop()
		}
		buf.timeout = time.AfterFunc(keyStoreTimeout, func() {
			k.mutex.Lock()
			defer k.mutex.Unlock()
			if nbuf := k.subnetBuffer[subnet]; nbuf == buf {
				delete(k.subnetBuffer, subnet)
			}
		})
		k.mutex.Unlock()
		k.sendKeyLookup(subnet.GetKey())
	}
}

func (k *keyStore) update(key ed25519.PublicKey) *keyInfo {
	k.mutex.Lock()
	var kArray keyArray
	copy(kArray[:], key)
	var info *keyInfo
	var packets [][]byte
	if info = k.keyToInfo[kArray]; info == nil {
		info = new(keyInfo)
		info.key = kArray
		info.address = *address.AddrForKey(ed25519.PublicKey(info.key[:]))
		info.subnet = *address.SubnetForKey(ed25519.PublicKey(info.key[:]))
		k.keyToInfo[info.key] = info
		k.addrToInfo[info.address] = info
		k.subnetToInfo[info.subnet] = info
		if buf := k.addrBuffer[info.address]; buf != nil {
			packets = append(packets, buf.packet)
			delete(k.addrBuffer, info.address)
		}
		if buf := k.subnetBuffer[info.subnet]; buf != nil {
			packets = append(packets, buf.packet)
			delete(k.subnetBuffer, info.subnet)
		}
	}
	k.resetTimeout(info)
	k.mutex.Unlock()
	for _, packet := range packets {
		k.core.WriteTo(packet, iwt.Addr(info.key[:]))
	}
	return info
}

func (k *keyStore) resetTimeout(info *keyInfo) {
	if info.timeout != nil {
		info.timeout.Stop()
	}
	info.timeout = time.AfterFunc(keyStoreTimeout, func() {
		k.mutex.Lock()
		defer k.mutex.Unlock()
		if nfo := k.keyToInfo[info.key]; nfo == info {
			delete(k.keyToInfo, info.key)
		}
		if nfo := k.addrToInfo[info.address]; nfo == info {
			delete(k.addrToInfo, info.address)
		}
		if nfo := k.subnetToInfo[info.subnet]; nfo == info {
			delete(k.subnetToInfo, info.subnet)
		}
	})
}

func (k *keyStore) oobHandler(fromKey, toKey ed25519.PublicKey, data []byte) {
	if len(data) != 1+ed25519.SignatureSize {
		return
	}
	sig := data[1:]
	switch data[0] {
	case typeKeyLookup:
		snet := *address.SubnetForKey(toKey)
		if snet == k.subnet && ed25519.Verify(fromKey, toKey[:], sig) {
			// This is looking for at least our subnet (possibly our address)
			// Send a response
			k.sendKeyResponse(fromKey)
		}
	case typeKeyResponse:
		// TODO keep a list of something to match against...
		// Ignore the response if it doesn't match anything of interest...
		if ed25519.Verify(fromKey, toKey[:], sig) {
			k.update(fromKey)
		}
	}
}

func (k *keyStore) sendKeyLookup(partial ed25519.PublicKey) {
	sig := ed25519.Sign(k.core.PrivateKey(), partial[:])
	bs := append([]byte{typeKeyLookup}, sig...)
	_ = k.core.SendOutOfBand(partial, bs)
}

func (k *keyStore) sendKeyResponse(dest ed25519.PublicKey) {
	sig := ed25519.Sign(k.core.PrivateKey(), dest[:])
	bs := append([]byte{typeKeyResponse}, sig...)
	_ = k.core.SendOutOfBand(dest, bs)
}

func (k *keyStore) readPC(p []byte) (int, error) {
	buf := make([]byte, k.core.MTU(), 65535)
	for {
		bs := buf
		n, from, err := k.core.ReadFrom(bs)
		if err != nil {
			return n, err
		}
		if n == 0 {
			continue
		}
		bs = bs[:n]
		if len(bs) == 0 {
			continue
		}
		if bs[0]&0xf0 != 0x60 {
			continue // not IPv6
		}
		if len(bs) < 40 {
			continue
		}
		k.mutex.Lock()
		mtu := int(k.mtu)
		k.mutex.Unlock()
		if len(bs) > mtu {
			// Using bs would make it leak off the stack, so copy to buf
			buf := make([]byte, 40)
			copy(buf, bs)
			ptb := &icmp.PacketTooBig{
				MTU:  mtu,
				Data: buf[:40],
			}
			if packet, err := CreateICMPv6(buf[8:24], buf[24:40], ipv6.ICMPTypePacketTooBig, 0, ptb); err == nil {
				_, _ = k.writePC(packet)
			}
			continue
		}
		var srcAddr, dstAddr address.Address
		var srcSubnet, dstSubnet address.Subnet
		copy(srcAddr[:], bs[8:])
		copy(dstAddr[:], bs[24:])
		copy(srcSubnet[:], bs[8:])
		copy(dstSubnet[:], bs[24:])
		if dstAddr != k.address && dstSubnet != k.subnet {
			fmt.Println(dstAddr, dstSubnet)
			continue // bad local address/subnet
		}
		info := k.update(ed25519.PublicKey(from.(iwt.Addr)))
		if srcAddr != info.address && srcSubnet != info.subnet {
			continue // bad remote address/subnet
		}
		n = copy(p, bs)
		return n, nil
	}
}

func (k *keyStore) writePC(bs []byte) (int, error) {
	if bs[0]&0xf0 != 0x60 {
		return 0, errors.New("not an IPv6 packet") // not IPv6
	}
	if len(bs) < 40 {
		strErr := fmt.Sprint("undersized IPv6 packet, length: ", len(bs))
		return 0, errors.New(strErr)
	}
	var srcAddr, dstAddr address.Address
	var srcSubnet, dstSubnet address.Subnet
	copy(srcAddr[:], bs[8:])
	copy(dstAddr[:], bs[24:])
	copy(srcSubnet[:], bs[8:])
	copy(dstSubnet[:], bs[24:])
	if srcAddr != k.address && srcSubnet != k.subnet {
		// This happens all the time due to link-local traffic
		// Don't send back an error, just drop it
		strErr := fmt.Sprint("incorrect source address: ", net.IP(srcAddr[:]).String(), " (destination: ", net.IP(dstAddr[:]).String(), ")")
        // fmt.Println(bs)
		return 0, errors.New(strErr)
	}
	if dstAddr.IsValid() {
		k.sendToAddress(dstAddr, bs)
	} else if dstSubnet.IsValid() {
		k.sendToSubnet(dstSubnet, bs)
	} else {
		// Check if the destination is the mDNS address. 
		fmt.Println(bs[24:40])
		if bs[24] == 0xff && bs[25] == 0x02 && bs[39] == 0xfb {
			fmt.Println("mDNS address")
			fmt.Println("length: ", len(bs[48:]))
			// fmt.Println("string: \"", string(bs[48:]), "\"")
			fmt.Println("bytes: ", bs)
			var msg dnsmessage.Message
			err := msg.Unpack(bs[48:])
			fmt.Println(msg)
			if err != nil {
				fmt.Println(err)
			} else {
				for _, q := range msg.Questions {
					fmt.Println("Question: ", q.Name.String())
					if strings.HasSuffix(q.Name.String(), ".ygg.local.") {
						fmt.Println("Looks like a real request")
						rsp := dnsmessage.Message{
							Header: dnsmessage.Header{Response: true, Authoritative: true},
							Answers: []dnsmessage.Resource{
								{
									Header:  dnsmessage.ResourceHeader{
										Name: q.Name,
										Type: dnsmessage.TypeAAAA,
										Class: dnsmessage.ClassINET,
									},
									Body: &dnsmessage.AAAAResource{ AAAA: [16]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15} },
								},
							},
						}
						buf, _ := rsp.Pack()
						/*
						builder := dnsmessage.NewBuilder(buf, dnsmessage.Header{msg.Header.ID, true, 0, true, false, false, false, dnsmessage.RCodeSuccess})
						builder.StartAnswers()
						builder.AAAAResource(dnsmessage.ResourceHeader{q.Name, 0, dnsmessage.ClassINET, 1, 0}, dnsmessage.AAAAResource{[16]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}})
						buf, err = builder.Finish()
						var msg2 dnsmessage.Message
						err := msg.Unpack(buf)
						fmt.Println(msg2)
						if err != nil { fmt.Println(err) }
						*/
						c := make([]byte, 0, 1024)
						// Copy over original IPv6 header
						c = append(c, bs[:48]...)
						// swap src and dst addresses
						copy(c[24:], srcAddr[:])
						copy(c[8:], dstAddr[:])
						c = append(c, buf[:]...)
						l := len(c)
						// set IPv6 content length
						c[4] = byte(l-40)
						// set UDP content length
						c[44] = byte(l-48)
						// swap UDP ports
						copy(c[40:42], bs[42:44])
						copy(c[42:44], bs[40:42])
						// set UDP checksum to 0
						c[46] = 0
						c[47] = 0
						fmt.Println("sending answer, len: ", len(c))
						fmt.Println(c)
						_, _ = k.writePC(c[:])
						fmt.Println("done")
					}
				}
			}
		}
		return 0, errors.New(fmt.Sprint("invalid destination address: ", net.IP(dstAddr[:]).String(), " (source: ", net.IP(srcAddr[:]).String()))
	}
	return len(bs), nil
}

// Exported API

func (k *keyStore) MaxMTU() uint64 {
	return k.core.MTU()
}

func (k *keyStore) SetMTU(mtu uint64) {
	if mtu > k.MaxMTU() {
		mtu = k.MaxMTU()
	}
	if mtu < 1280 {
		mtu = 1280
	}
	k.mutex.Lock()
	k.mtu = mtu
	k.mutex.Unlock()
}

func (k *keyStore) MTU() uint64 {
	k.mutex.Lock()
	mtu := k.mtu
	k.mutex.Unlock()
	return mtu
}

type ReadWriteCloser struct {
	keyStore
}

func NewReadWriteCloser(c *core.Core) *ReadWriteCloser {
	rwc := new(ReadWriteCloser)
	rwc.init(c)
	return rwc
}

func (rwc *ReadWriteCloser) Address() address.Address {
	return rwc.address
}

func (rwc *ReadWriteCloser) Subnet() address.Subnet {
	return rwc.subnet
}

func (rwc *ReadWriteCloser) Read(p []byte) (n int, err error) {
	return rwc.readPC(p)
}

func (rwc *ReadWriteCloser) Write(p []byte) (n int, err error) {
	return rwc.writePC(p)
}

func (rwc *ReadWriteCloser) Close() error {
	err := rwc.core.Close()
	rwc.core.Stop()
	return err
}
