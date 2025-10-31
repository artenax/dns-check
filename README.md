This utility allows you to resolve the IP address of a domain, HTTP2/3 and ECH support from the DNS response, and hosting. DoH is supported.

# Usage
```
dns-check --help
dns-check +cloudflare-dns.com google.com
```

# Build
```
git clone https://github.com/artenax/dns-check
cd dns-check
go mod init example.com/myapp
go mod tidy
export GOMAXPROCS=1
export GOOS=windows
export GOARCH=386
go build -ldflags="-s -w" dns-check.go
```
