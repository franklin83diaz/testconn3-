
### ARM

64bit
 GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o test3-arm64 cmd/client/main.go 

32bit
 GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -o test332 cmd/client/main.go