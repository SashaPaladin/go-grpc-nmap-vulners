build:
	protoc --proto_path=proto proto/*.proto --go_out=proto
	protoc --proto_path=proto proto/*.proto --go-grpc_out=proto
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.45.2
	docker-compose build nmap-vulners

run:
	docker-compose up nmap-vulners

lint:
	golangci-lint run ./...

test:
	go test ./pkg/server/...