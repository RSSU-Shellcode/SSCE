export GOOS=windows
export GOARCH=386
go test -v
export GOARCH=amd64
go test -v