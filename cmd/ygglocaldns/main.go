package main

import (
	"fmt"
	"log"
	"strconv"
	"flag"
	"io/ioutil"
	"net"
	"crypto/ed25519"
	"encoding/hex"

	"github.com/miekg/dns"
	"github.com/hjson/hjson-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

type args struct {
	useconffile    string
	port           int
	address        string
	domain         string
}

func getArgs() args {
	useconffile := flag.String("useconffile", "conf", "config file to read the private key from")
	port := flag.Int("port", 55353, "port to listen on (UDP)")
	address := flag.String("address", "", "the address to bind to")
	domain := flag.String("domain", ".", "the domain to answer for")
	flag.Parse()
	return args{
		useconffile: *useconffile,
		port: *port,
		address: *address,
		domain: *domain,
	}
}

var privateKey []byte

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			new_seed := make([]byte, 32)
			name := q.Name[0:len(q.Name)-1]
	        for index := 0; index < len(new_seed); index++ {
				new_seed[index] = privateKey[index] ^ name[index % len(name)]
			}

			address := address.AddrForKey(ed25519.NewKeyFromSeed(new_seed).Public().(ed25519.PublicKey))
			ip := net.IP(address[:]).String()
			log.Println(ip)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func main() {
	args := getArgs()

	conf, err := ioutil.ReadFile(args.useconffile)
	var cfg map[string]interface{}
	err = hjson.Unmarshal(conf, &cfg)
    if err != nil {
        panic(err)
    }

	// fmt.Println(cfg["PrivateKey"])
	sigPriv, _ := hex.DecodeString(cfg["PrivateKey"].(string))
	privateKey = sigPriv[0:32]

	// attach request handler func
	dns.HandleFunc(args.domain, handleDnsRequest)

	// start server
	port := args.port
	server := &dns.Server{Addr: args.address + ":" + strconv.Itoa(port), Net: "udp"}
	server.MsgAcceptFunc = func(dh dns.Header) dns.MsgAcceptAction {
		return dns.MsgAccept
	}
	log.Printf("Starting at %d\n", port)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
