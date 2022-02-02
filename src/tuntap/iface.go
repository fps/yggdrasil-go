package tuntap

import (
	"fmt"
	"strings"
	"golang.org/x/net/dns/dnsmessage"
	"github.com/google/gopacket"
)	

const TUN_OFFSET_BYTES = 4

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
            var msg dnsmessage.Message
            err := msg.Unpack(bs[48:])
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
									//Name: dnsmessage.MustNewName("quark.bark.org."),
									Name: q.Name,
									Type: dnsmessage.TypeAAAA,
									Class: dnsmessage.ClassINET,
									TTL: 10,
								},
								// Body: &dnsmessage.AAAAResource{ AAAAA: [4]byte{ 127, 0, 0, 1} },
								Body: &dnsmessage.AAAAResource{ AAAA: address },
								//Body: &dnsmessage.AAAAResource{ AAAA: [16]byte{0xff,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15} },
							},
						},
					}
					rspbuf, err := rsp.Pack()
					if  err != nil { fmt.Println("Error packing: ", err) }
					fmt.Println(rsp.GoString())
					c := make([]byte, 0, 1024)

					// Copy over original IPv6 header
					c = append(c, 0x00, 0x00, 0x00, 0x00)
					c = append(c, bs[:48]...)
					c = append(c, rspbuf[:]...)
					l := len(rspbuf)

					// set IPv6 content length
					c[5+4] = byte(l+8)
					c[4+4] = 0x00

					// set UDP content length
					c[45+4] = byte(l+8)
					c[44+4] = 0x00

					// set UDP checksum
					c[46+4] = 0xff
					c[47+4] = 0xff

					tun.iface.Write(c[:], TUN_OFFSET_BYTES)
					fmt.Println("done")
				}
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
