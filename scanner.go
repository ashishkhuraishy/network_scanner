package network_scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
)

func Scan() {
	fmt.Println("Scan Called")

	cidr, err := getCIDR()

	if err != nil {
		log.Fatalln(err)
	}

	listAllIPs(cidr)

}

func getCIDR() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			cidr := addr

			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return cidr.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

func listAllIPs(cidr string) []string {
	var IPs []string

	_, ipv4, err := net.ParseCIDR(cidr)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ipv4.IP, ipv4.Mask)

	start := binary.BigEndian.Uint32(ipv4.IP)
	mask := binary.BigEndian.Uint32(ipv4.Mask)

	finish := (start & mask) | (mask ^ 0xffffffff)

	fmt.Println(start, mask, finish)

	for i := start; i < finish; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)

		IPs = append(IPs, ip.String())
	}

	return IPs
}
