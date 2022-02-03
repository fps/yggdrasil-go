package tuntap

import (
	"fmt"
	"strings"
	"crypto/ed25519"
	"encoding/hex"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"golang.org/x/net/dns/dnsmessage"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const TUN_OFFSET_BYTES = 4

func MixinHostname(masterKey ed25519.PrivateKey, hostname string) ed25519.PrivateKey {
	sigPrivSlice := masterKey[0:32]
	for index := 0; index < len(sigPrivSlice); index++ {
		sigPrivSlice[index] = sigPrivSlice[index] ^ hostname[index % len(hostname)]
	}
	return ed25519.NewKeyFromSeed(sigPrivSlice)
}

func (tun *TunAdapter) handle_mDNS(bs []byte) {
	packet := gopacket.NewPacket(bs, layers.LayerTypeIPv6, gopacket.Default)

	ip := packet.Layer(layers.LayerTypeIPv6)
	if ip == nil {
		// fmt.Println("no ip layer")
		return
	}
	// fmt.Println(ip.(*layers.IPv6).SrcIP)
	udp := packet.Layer(layers.LayerTypeUDP);
	 if udp == nil {
		// fmt.Println("no udp layer")
		return
	}
	// fmt.Println(udp.(*layers.UDP).Payload)

	var msg dnsmessage.Message
	err := msg.Unpack(udp.(*layers.UDP).Payload)
	// fmt.Println(msg)
	if err != nil {
		fmt.Println("Error unpacking: ", err)
		return
	} else {
		for _, q := range msg.Questions {
			if q.Type != dnsmessage.TypeAAAA { continue }
			if !strings.HasSuffix(q.Name.String(), ".ygg.local.") { continue }

			fmt.Println("Got an mDNS request")
			masterKey, err := hex.DecodeString(tun.config.MasterKey)
			mixedPriv := MixinHostname(ed25519.PrivateKey(masterKey), strings.TrimSuffix(q.Name.String(), ".ygg.local."))
			resolved := address.AddrForKey(mixedPriv.Public().(ed25519.PublicKey))
			rsp := dnsmessage.Message{
				Header: dnsmessage.Header{ ID: msg.Header.ID, Response: true, Authoritative: true },
				Questions: []dnsmessage.Question{},
				Answers: []dnsmessage.Resource{
					{
						Header:  dnsmessage.ResourceHeader{
							Name: q.Name,
							Type: dnsmessage.TypeAAAA,
							Class: dnsmessage.ClassINET,
							TTL: 10,
						},
						Body: &dnsmessage.AAAAResource{ AAAA: *resolved },
					},
				},
			}
			rspbuf, err := rsp.Pack()
			if  err != nil {
				fmt.Println("Error packing: ", err)
				return
			}

			// fmt.Println("dns message length: ", len(rspbuf))

			ipp := *(ip.(*layers.IPv6))
			udpp := *(udp.(*layers.UDP))
			udpp.SetNetworkLayerForChecksum(&ipp)
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{ FixLengths: true, ComputeChecksums: true, }

			gopacket.SerializeLayers(buf, opts, 
				&ipp,
				&udpp,
				gopacket.Payload(rspbuf[:]),
			)

			// fmt.Println("final size: ", len(buf.Bytes()))

			out_buf := make([]byte, 0, 65553)
			out_buf = append(out_buf, 0x00, 0x00, 0x00, 0x00)
			out_buf = append(out_buf, buf.Bytes()...)

			tun.iface.Write(out_buf[:], TUN_OFFSET_BYTES)
			// fmt.Println("done")
		}
    }
}

func (tun *TunAdapter) read() {
	var buf [TUN_OFFSET_BYTES + 65535]byte
	for {
		n, err := tun.iface.Read(buf[:], TUN_OFFSET_BYTES)
		if n <= TUN_OFFSET_BYTES || err != nil {
			tun.log.Errorln("Error reading TUN:", err)
			ferr := tun.iface.Flush()
			if ferr != nil {
				tun.log.Errorln("Unable to flush packets:", ferr)
			}
			return
		}
		begin := TUN_OFFSET_BYTES
		end := begin + n
		bs := buf[begin:end]
		if tun.config.MixinHostname {
			if bs[24] == 0xff && bs[25] == 0x02 && bs[39] == 0xfb {
	            tun.handle_mDNS(bs)
			}
		}
		if _, err := tun.rwc.Write(bs); err != nil {
			tun.log.Debugln("Unable to send packet:", err)
		}
	}
}

func (tun *TunAdapter) write() {
	var buf [TUN_OFFSET_BYTES + 65535]byte
	for {
		bs := buf[TUN_OFFSET_BYTES:]
		n, err := tun.rwc.Read(bs)
		if err != nil {
			tun.log.Errorln("Exiting tun writer due to core read error:", err)
			return
		}
		if !tun.isEnabled {
			continue // Nothing to do, the tun isn't enabled
		}
		bs = buf[:TUN_OFFSET_BYTES+n]
		if _, err = tun.iface.Write(bs, TUN_OFFSET_BYTES); err != nil {
			tun.Act(nil, func() {
				if !tun.isOpen {
					tun.log.Errorln("TUN iface write error:", err)
				}
			})
		}
	}
}
