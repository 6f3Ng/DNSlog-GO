package Dns

import (
	"DnsLog/Core"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var DnsData = make(map[string][]DnsInfo)

var rw sync.RWMutex

type DnsInfo struct {
	Subdomain string
	Ipaddress string
	Time      int64
}

var D DnsInfo

// ListingDnsServer 监听dns端口
func ListingDnsServer() {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		log.Fatal("Please run as root")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()
	log.Println("DNS Listing Start...")
	for {
		buf := make([]byte, 512)
		_, addr, _ := conn.ReadFromUDP(buf)
		var msg dnsmessage.Message
		if err := msg.Unpack(buf); err != nil {
			fmt.Println(err)
			continue
		}
		go serverDNS(addr, conn, msg)
	}
}

func serverDNS(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message) {
	if len(msg.Questions) < 1 {
		return
	}
	question := msg.Questions[0]
	var (
		queryNameStr = question.Name.String()
		queryType    = question.Type
		queryName, _ = dnsmessage.NewName(queryNameStr)
		resource     dnsmessage.Resource
		queryDoamin  = strings.Replace(queryNameStr, fmt.Sprintf(".%s.", Core.Config.Dns.Dnslog), "", 1)
	)
	var resIp [4]byte
	// fmt.Println(queryNameStr[:len(queryNameStr)-1], " ", Core.Config.Dns.Xip)
	// 域名过滤，避免网络扫描
	if strings.HasSuffix(queryNameStr[:len(queryNameStr)-1], Core.Config.Dns.Dnslog) {
		token := strings.Split(queryDoamin, ".")
		user := Core.GetUser(token[len(token)-1])
		D.Set(user, DnsInfo{
			Subdomain: queryNameStr[:len(queryNameStr)-1],
			Ipaddress: addr.IP.String(),
			Time:      time.Now().Unix(),
		})
		resIp = [4]byte{127, 0, 0, 1}
	} else if strings.HasSuffix(queryNameStr[:len(queryNameStr)-1], Core.Config.Dns.Xip) {
		// xip解析
		// queryDoamin := strings.Replace(queryNameStr, fmt.Sprintf(".%s.", Core.Config.Dns.Dnslog), "", 1)
		reg := regexp.MustCompile(`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}`)
		if reg == nil {
			return
		}
		resIpStr := reg.FindString(queryDoamin)
		//fmt.Println(resIpStr)
		if resIpStr == "" {
			resIp = [4]byte{127, 0, 0, 1}
		} else {
			// ip转换 string -> byte
			// resIpStrArray := strings.Split(resIpStr, ".")
			// resIpNum0, _ := strconv.Atoi(resIpStrArray[0])
			// resIpNum1, _ := strconv.Atoi(resIpStrArray[1])
			// resIpNum2, _ := strconv.Atoi(resIpStrArray[2])
			// resIpNum3, _ := strconv.Atoi(resIpStrArray[3])
			// resIp[0] = byte(resIpNum0)
			// resIp[1] = byte(resIpNum1)
			// resIp[2] = byte(resIpNum2)
			// resIp[3] = byte(resIpNum3)
			ip := net.ParseIP(resIpStr)
			ip4 := net.IP.To4(ip)
			resIp = [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
			// for i := 0; i < len(ip4); i++ {
			// 	resIp[i] = ip4[i]
			// }
		}
	} else {
		return
	}
	switch queryType {
	case dnsmessage.TypeA:
		resource = NewAResource(queryName, resIp)
	default:
		resource = NewAResource(queryName, resIp)
	}
	// send response
	msg.Response = true
	msg.Answers = append(msg.Answers, resource)
	Response(addr, conn, msg)
}

// Response return
func Response(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message) {
	packed, err := msg.Pack()
	if err != nil {
		fmt.Println(err)
		return
	}
	if _, err := conn.WriteToUDP(packed, addr); err != nil {
		fmt.Println(err)
	}
}

func NewAResource(query dnsmessage.Name, a [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  query,
			Class: dnsmessage.ClassINET,
			TTL:   0,
		},
		Body: &dnsmessage.AResource{
			A: a,
		},
	}
}

func (d *DnsInfo) Set(token string, data DnsInfo) {
	rw.Lock()
	if DnsData[token] == nil {
		DnsData[token] = []DnsInfo{data}
	} else {
		DnsData[token] = append(DnsData[token], data)
	}
	rw.Unlock()
}

func (d *DnsInfo) Get(token string) string {
	rw.RLock()
	res := ""
	if DnsData[token] != nil {
		v, _ := json.Marshal(DnsData[token])
		res = string(v)
	}
	if res == "" {
		res = "null"
	}
	rw.RUnlock()
	return res
}

func (d *DnsInfo) Clear(token string) {
	DnsData[token] = []DnsInfo{}
	DnsData["other"] = []DnsInfo{}
}
