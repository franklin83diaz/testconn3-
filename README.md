
### ARM

64bit
 GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o test3-arm64 cmd/client/main.go 

32bit
 GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -o test332 cmd/client/main.go


### Windows 64-bit:

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
go build -trimpath -buildvcs=false -ldflags="-s -w" \
-o client.exe cmd/client/main.go

### Windows 32-bit:

GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o client.exe cmd/client/main.go

### Windows ARM64:

GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o client.exe cmd/client/main.go
