set GOOS=windows
set GOARCH=386
go test -v
set GOARCH=amd64
go test -v