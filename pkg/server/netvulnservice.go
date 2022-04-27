package server

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	pb "go-grpc-nmap-vulners/proto"
	"log"
	"strconv"
	"strings"
	"time"
)

type NetVulnServiceServer struct {
	pb.UnimplementedNetVulnServiceServer
}

func (NetVulnServiceServer) CheckVuln(ctx context.Context, request *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error) {
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ports := portsToString(request.TcpPort)

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(request.Targets...),
		nmap.WithPorts(strings.Join(ports, ",")),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners.nse"),
		nmap.WithContext(ctx1),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}
	var tarResult []*pb.TargetResult
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		var ser []*pb.Service
		var vuln []*pb.Vulnerability
		for _, port := range host.Ports {
			for _, script := range port.Scripts {
				for _, table := range script.Tables {
					for _, table2 := range table.Tables {
						var id string
						var cvss float64
						for _, element := range table2.Elements {
							if element.Key == "id" {
								id = element.Value
							}
							if element.Key == "cvss" {
								cvss, _ = strconv.ParseFloat(element.Value, 64)
							}
						}
						vuln = append(vuln, &pb.Vulnerability{Identifier: id, CvssScore: float32(cvss)})
					}
				}
				ser = append(ser, &pb.Service{Name: port.Service.Name, Version: port.Service.Version, TcpPort: int32(port.ID), Vulns: vuln})
			}
		}
		tarResult = append(tarResult, &pb.TargetResult{Target: fmt.Sprintf("%s", host.Addresses[0]), Services: ser}) // string() не работает с таким типом...
	}
	return &pb.CheckVulnResponse{Results: tarResult}, err
}

func portsToString(sl []int32) []string {
	var stringSlice []string
	for i := range sl {
		number := sl[i]
		text := strconv.Itoa(int(number))
		stringSlice = append(stringSlice, text)
	}
	return stringSlice
}
