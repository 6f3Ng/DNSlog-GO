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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var DnsData []DnsInfo

var rw sync.RWMutex

type DnsInfo struct {
	Subdomain string
	Ipaddress string
	Time      int64
}

var D DnsInfo

//监听dns端口
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
		//queryTypeStr = question.Type.String()
		queryNameStr = question.Name.String()
		queryType    = question.Type
		queryName, _ = dnsmessage.NewName(queryNameStr)
	)
	var resIp [4]byte
	//fmt.Println(queryNameStr[:len(queryNameStr)-1], " ", Core.Config.Dns.Xip)
	//域名过滤，避免网络扫描
	if strings.HasSuffix(queryNameStr[:len(queryNameStr)-1], Core.Config.Dns.Dnslog) {
		D.Set(DnsInfo{
			Subdomain: queryNameStr[:len(queryNameStr)-1],
			Ipaddress: addr.IP.String(),
			Time:      time.Now().Unix(),
		})
		resIp = [4]byte{127, 0, 0, 1}
	} else if strings.HasSuffix(queryNameStr[:len(queryNameStr)-1], Core.Config.Dns.Xip) {
		D.Set(DnsInfo{
			Subdomain: queryNameStr[:len(queryNameStr)-1],
			Ipaddress: addr.IP.String(),
			Time:      time.Now().Unix(),
		})
		reg := regexp.MustCompile(`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}`)
		if reg == nil {
			return
		}
		resIpStr := reg.FindString(queryNameStr)
		//fmt.Println(resIpStr)
		if resIpStr == "" {
			resIp = [4]byte{127, 0, 0, 1}
		} else {
			resIpStrArray := strings.Split(resIpStr, ".")
			resIpNum0, _ := strconv.Atoi(resIpStrArray[0])
			resIpNum1, _ := strconv.Atoi(resIpStrArray[1])
			resIpNum2, _ := strconv.Atoi(resIpStrArray[2])
			resIpNum3, _ := strconv.Atoi(resIpStrArray[3])
			resIp[0] = byte(resIpNum0)
			resIp[1] = byte(resIpNum1)
			resIp[2] = byte(resIpNum2)
			resIp[3] = byte(resIpNum3)
		}
	} else {
		return
	}
	var resource dnsmessage.Resource
	switch queryType {
	case dnsmessage.TypeA:
		resource = NewAResource(queryName, resIp)
	default:
		//fmt.Printf("not support dns queryType: [%s] \n", queryType.String())
		return
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
			TTL:   120,
		},
		Body: &dnsmessage.AResource{
			A: a,
		},
	}
}

func (d *DnsInfo) Set(data DnsInfo) {
	rw.Lock()
	DnsData = append(DnsData, data)
	rw.Unlock()
}

func (d *DnsInfo) Get() string {
	rw.RLock()
	v, _ := json.Marshal(DnsData)
	rw.RUnlock()
	return string(v)
}

func (d *DnsInfo) Clear() {
	DnsData = (DnsData)[0:0]
}
