package server

import (
	"context"
	pb "go-grpc-nmap-vulners/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"log"
	"net"
	"testing"
)

func TestCheckVuln(t *testing.T) {
	tests := []struct {
		name   string
		req    *pb.CheckVulnRequest
		res    *pb.CheckVulnResponse
		errMsg string
	}{
		{
			"testWithOneTargetAndPort",
			&pb.CheckVulnRequest{
				Targets: []string{"damnvulnerableiosapp.com"},
				TcpPort: []int32{22},
			},
			&pb.CheckVulnResponse{Results: []*pb.TargetResult{
				{Target: "160.153.63.197", Services: []*pb.Service{
					{Name: "ssh", Version: "5.3", TcpPort: 22, Vulns: []*pb.Vulnerability{
						{
							Identifier: "MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/",
							CvssScore:  7.5,
						},
					}},
				}},
			}},
			"",
		},
		{
			"testWithOneTargetAndTwoPorts",
			&pb.CheckVulnRequest{
				Targets: []string{"damnvulnerableiosapp.com"},
				TcpPort: []int32{587, 22},
			},
			&pb.CheckVulnResponse{Results: []*pb.TargetResult{
				{Target: "160.153.63.197", Services: []*pb.Service{
					{Name: "ssh", Version: "5.3", TcpPort: 22, Vulns: []*pb.Vulnerability{
						{
							Identifier: "MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/",
							CvssScore:  7.5,
						},
					}},
					{Name: "smtp", Version: "4.94.2", TcpPort: 587, Vulns: []*pb.Vulnerability{
						{
							Identifier: "MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/",
							CvssScore:  7.5,
						},
					}},
				}},
			}},
			"",
		},
		{
			"testWithTwoTargetsAndPorts",
			&pb.CheckVulnRequest{
				Targets: []string{"damnvulnerableiosapp.com", "defendtheweb.net"},
				TcpPort: []int32{587, 22},
			},
			&pb.CheckVulnResponse{Results: []*pb.TargetResult{
				{Target: "160.153.63.197", Services: []*pb.Service{
					{Name: "ssh", Version: "5.3", TcpPort: 22, Vulns: []*pb.Vulnerability{
						{
							Identifier: "MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/",
							CvssScore:  7.5,
						},
					}},
					{Name: "smtp", Version: "4.94.2", TcpPort: 587, Vulns: []*pb.Vulnerability{
						{
							Identifier: "MSF:ILITIES/OPENBSD-OPENSSH-CVE-2010-4478/",
							CvssScore:  7.5,
						},
					}},
				}},
				{Target: "3.10.42.19", Services: []*pb.Service{
					{Name: "ssh", Version: "7.6p1 Ubuntu 4ubuntu0.5", TcpPort: 22, Vulns: []*pb.Vulnerability{
						{
							Identifier: "2C119FFA-ECE0-5E14-A4A4-354A2C38071A",
							CvssScore:  10.0,
						},
					}},
				}},
			}},
			"",
		},
	}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := grpc.DialContext(ctx, "", grpc.WithInsecure(), grpc.WithContextDialer(dialer()))
			if err != nil {
				log.Fatal(err)
			}
			client := pb.NewNetVulnServiceClient(conn)
			defer conn.Close()

			request := &pb.CheckVulnRequest{Targets: tt.req.Targets, TcpPort: tt.req.TcpPort}
			response, err := client.CheckVuln(ctx, request)
			if response != nil {
				var targetRec []string
				var targetExp []string
				var serviceRec []string
				var serviceExp []string
				var vulnRec []string
				var vulnExp []string
				for _, r := range response.Results {
					for _, s := range r.Services {
						serviceRec = append(serviceRec, s.Name, s.Version, string(s.TcpPort))
						for _, v := range s.Vulns {
							vulnRec = append(vulnRec, v.Identifier)
							break
						}
					}
				}
				for _, r := range tt.res.Results {
					targetExp = append(targetExp, r.Target)
					for _, s := range r.Services {
						serviceExp = append(serviceExp, s.Name, s.Version, string(s.TcpPort))
						for _, v := range s.Vulns {
							vulnExp = append(vulnExp, v.Identifier)
						}
					}
				}
				for i, p := range targetRec {
					if p != targetExp[i] {
						t.Error("error: expected", targetExp, "received", targetRec)
					}
				}
				for i, p := range serviceRec {
					if p != serviceExp[i] {
						t.Error("error: expected", targetExp, "received", targetRec)
					}
				}
				for i, p := range vulnRec {
					if p != vulnExp[i] {
						t.Error("error: expected", targetExp, "received", targetRec)
					}
				}
			}
			if err != nil {
				if er, ok := status.FromError(err); ok {
					if er.Message() != tt.errMsg {
						t.Error("error: expected", tt.errMsg, "received", er.Message())
					}
				}
			}
		})
	}
}

func dialer() func(context.Context, string) (net.Conn, error) {
	listener := bufconn.Listen(1024 * 1024)

	server := grpc.NewServer()

	pb.RegisterNetVulnServiceServer(server, &NetVulnServiceServer{})

	go func() {
		if err := server.Serve(listener); err != nil {
			log.Fatal(err)
		}
	}()

	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}
