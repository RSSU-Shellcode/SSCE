# SSCE
A simple shellcode encoder, build and erase decoder at runtime and erase shellcode after execution.

## Usage
```bash
ssce -arch 64 -i shellcode.bin -o shellcode_x64.bin
```

## Development
```go
package main

import (
    "encoding/hex"
    "fmt"
    "os"

    "github.com/RSSU-Shellcode/SSCE"
)

func main() {
    encoder := ssce.NewEncoder()

    shellcode, err := os.ReadFile("shellcode.bin")
    checkError(err)
    opts := ssce.Options{
        SaveContext: true,
        EraseInst:   true,
    }

    shellcode, err = encoder.Encode(shellcode, 64, &opts)
    checkError(err)

    out := hex.EncodeToString(shellcode)
    fmt.Println(out)

    err = encoder.Close()
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
```
