package main

import (
	"github.com/spf13/viper"
	"go-grpc-nmap-vulners/pkg/server"
	pb "go-grpc-nmap-vulners/proto"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	if err := initConfig(); err != nil {
		log.Fatalf("faliled to initialize configs: %s", err)
	}

	lis, err := net.Listen("tcp", ":"+viper.GetString("server.port"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var s = &server.NetVulnServiceServer{}
	grpcServer := grpc.NewServer()
	pb.RegisterNetVulnServiceServer(grpcServer, s)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to server: %v", err)
	}
}

func initConfig() error {
	viper.AddConfigPath("cfg")
	viper.SetConfigName("config")
	return viper.ReadInConfig()
}
