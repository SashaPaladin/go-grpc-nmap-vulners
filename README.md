# go-grpc-nmap-vulners

### Для сбори и запуска приложения:

```
make build
make run
```

### Для запуска линтера:

```
make lint
```

### Для запуска тестов:

```
make test
```

## Описание сервиса:

#### gRPC сервис обертка над nmap с использованием скрипта https://github.com/vulnersCom/nmap-vulners

#### proto:
```
syntax = "proto3";
package netvuln.v1;

option go_package = ".";

service NetVulnService {
  rpc CheckVuln(CheckVulnRequest) returns (CheckVulnResponse);
}

message CheckVulnRequest {
  repeated string targets = 1; // IP addresses
  repeated int32 tcp_port = 2; // only TCP ports
}

message CheckVulnResponse {
  repeated TargetResult results = 1;
}

message TargetResult {
  string target = 1; // target IP
  repeated Service services = 2;
}

message Service {
  string name = 1;
  string version = 2;
  int32 tcp_port = 3;
  repeated Vulnerability vulns = 4;
}

message Vulnerability {
  string identifier = 1;
  float cvss_score = 2;
}
```

#### Результат выполнения с 160.153.63.197:587:

```
Target: 160.153.63.197
        Name: smtp, Version: 4.94.2, Tcp_port: 587
                 Identifier: CVE-2020-28026, Cvss_score: 9.300000
                 Identifier: CVE-2020-28021, Cvss_score: 9.000000
                 Identifier: CVE-2020-28024, Cvss_score: 7.500000
                 Identifier: CVE-2020-28022, Cvss_score: 7.500000
                 Identifier: CVE-2020-28018, Cvss_score: 7.500000
                 Identifier: CVE-2020-28016, Cvss_score: 7.200000
                 Identifier: CVE-2020-28015, Cvss_score: 7.200000
                 Identifier: CVE-2020-28013, Cvss_score: 7.200000
                 Identifier: CVE-2020-28012, Cvss_score: 7.200000
                 Identifier: CVE-2020-28011, Cvss_score: 7.200000
                 Identifier: CVE-2020-28010, Cvss_score: 7.200000
                 Identifier: CVE-2020-28009, Cvss_score: 7.200000
                 Identifier: CVE-2020-28008, Cvss_score: 7.200000
                 Identifier: CVE-2020-28007, Cvss_score: 7.200000
                 Identifier: CVE-2021-27216, Cvss_score: 6.300000
                 Identifier: CVE-2020-28014, Cvss_score: 5.600000
                 Identifier: CVE-2021-38371, Cvss_score: 5.000000
                 Identifier: CVE-2020-28025, Cvss_score: 5.000000
                 Identifier: CVE-2020-28023, Cvss_score: 5.000000
                 Identifier: CVE-2020-28019, Cvss_score: 5.000000
```
