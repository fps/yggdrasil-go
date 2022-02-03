package tuntap

import (
	"fmt"
	"strings"
	"golang.org/x/net/dns/dnsmessage"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)	

const TUN_OFFSET_BYTES = 4

func (tun *TunAdapter) handle_mDNS(bs []byte) {
	packet := gopacket.NewPacket(bs, layers.LayerTypeIPv6, gopacket.Default)
	/*
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
	*/

	ip := packet.Layer(layers.LayerTypeIPv6)
	if ip == nil { 
		fmt.Println("no ip layer")
		return 
	}
	fmt.Println(ip.(*layers.IPv6).SrcIP)
	udp := packet.Layer(layers.LayerTypeUDP);
	 if udp == nil { 
		fmt.Println("no udp layer")
		return 
	}
	fmt.Println(udp.(*layers.UDP).Payload)

	var msg dnsmessage.Message
	err := msg.Unpack(udp.(*layers.UDP).Payload)
	// fmt.Println(msg)
	if err != nil {
		fmt.Println("Error unpacking: ", err)
	} else {
		for _, q := range msg.Questions {
			if q.Type != dnsmessage.TypeAAAA { continue }
			if !strings.HasSuffix(q.Name.String(), ".ygg.local.") { continue } 

			fmt.Println("###### Looks like a real request")
			var address [16]byte
			copy(address[:], bs[8:24])
			rsp := dnsmessage.Message{
				Header: dnsmessage.Header{ ID: msg.Header.ID, Response: true, Authoritative: false },
				Questions: []dnsmessage.Question{ q },
				Answers: []dnsmessage.Resource{
					{
						Header:  dnsmessage.ResourceHeader{
							Name: q.Name,
							Type: dnsmessage.TypeAAAA,
							Class: dnsmessage.ClassINET,
							TTL: 10,
						},
						Body: &dnsmessage.AAAAResource{ AAAA: address },
						//Body: &dnsmessage.AAAAResource{ AAAA: [16]byte{0xff,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15} },
					},
				},
			}
			rspbuf, err := rsp.Pack()
			if  err != nil { 
				fmt.Println("Error packing: ", err) 
				return
			}

			buf := gopacket.NewSerializeBuffer()
			// opts := gopacket.SerializeOptions{}
			opts := gopacket.SerializeOptions{ FixLengths: true, ComputeChecksums: true, }
			gopacket.SerializeLayers(buf, opts, 
				&layers.IPv6{ Version: ip.(*layers.IPv6).Version, },
				&layers.UDP{},
				gopacket.Payload(rspbuf),
			)
			
			out_buf := make([]byte, 0, 65553)
			out_buf = append(out_buf, 0x00, 0x00, 0x00, 0x00)
			out_buf = append(out_buf, buf.Bytes()...)

			tun.iface.Write(out_buf[:], TUN_OFFSET_BYTES)
			fmt.Println("done")
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
		if bs[24] == 0xff && bs[25] == 0x02 && bs[39] == 0xfb {
            tun.handle_mDNS(bs)
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
