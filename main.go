package main

import (
	"DnsLog/Core"
	"DnsLog/Dns"
	"DnsLog/Http"

	"log"
	"strings"

	"gopkg.in/gcfg.v1"
)

//GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-w -s" main.go

func main() {
	var err = gcfg.ReadFileInto(&Core.Config, "./config.ini")
	if err != nil {
		log.Fatalln(err.Error())
	}
	for _, v := range strings.Split(Core.Config.HTTP.Token, ",") {
		Core.User[v] = Core.GetRandStr()
	}
	go Dns.ListingDnsServer()
	Http.ListingHttpManagementServer()
}
