package tuntap

import (
	"fmt"
	"strings"
	"golang.org/x/net/dns/dnsmessage"
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
            fmt.Println(msg)
            if err != nil {
                fmt.Println(err)
            } else {
                for _, q := range msg.Questions {
                    fmt.Println("Question: ", q.Name.String())
                    if strings.HasSuffix(q.Name.String(), ".ygg.local.") {
                        fmt.Println("###### Looks like a real request")
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
                        rspbuf, _ := rsp.Pack()
                        fmt.Println(rsp)
                        c := make([]byte, 0, 1024)
                        // Copy over original IPv6 header
						c = append(c, 0x00, 0x00, 0x00, 0x00)
                        c = append(c, bs[:48]...)
                        // swap src and dst addresses
                        // copy(c[24:], srcAddr[:])
                        // copy(c[8:], dstAddr[:])
                        c = append(c, rspbuf[:]...)
                        l := len(c)
                        // set IPv6 content length
                        c[4+4] = byte(l-40)
                        // set UDP content length
                        c[44+4] = byte(l-48)
                        // swap UDP ports
                        // copy(c[40:42], bs[42:44])
                        // copy(c[42:44], bs[40:42])
                        // set UDP checksum to 0
                        c[46+4] = 0
                        c[47+4] = 0
                        fmt.Println("sending answer, len: ", len(c))
                        // fmt.Println(c)
                        // _, _ = k.core.WriteTo(c[:], net.Addr{"udp", net.IP(dstAddr[:]).String()})
                        // _, _ = k.readPC(c)
                        // defer k.writePC(c)
                        // k.sendToAddress(dstAddr, c)
						// tun.iface.Write(c, 0)
						tun.iface.Write(c[:], TUN_OFFSET_BYTES)
                        fmt.Println("done")
					}
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
