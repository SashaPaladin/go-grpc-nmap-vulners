FROM golang:latest

RUN go version
ENV GOPATH=/

COPY ./ ./

RUN apt-get update
RUN apt-get install nmap -y
RUN mkdir vuln
RUN git clone https://github.com/vulnersCom/nmap-vulners vuln
RUN cp -a vuln/vulners.nse /usr/share/nmap/scripts
RUN cp -a vuln/http-vulners-regex.nse /usr/share/nmap/scripts
RUN cp -a vuln/http-vulners-regex.json /usr/share/nmap/nselib/data
RUN cp -a vuln/http-vulners-paths.txt /usr/share/nmap/nselib/data
RUN cp -a vuln/vulners.nse .
RUN cp -a vuln/http-vulners-regex.nse .
RUN cp -a vuln/http-vulners-regex.json .
RUN cp -a vuln/http-vulners-paths.txt .
RUN nmap --script-updatedb

RUN go mod download
RUN go build -o nmap-vulners ./cmd/main.go

EXPOSE 8000

CMD ["./nmap-vulners"]
