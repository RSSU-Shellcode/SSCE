package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RSSU-Shellcode/SSCE"
)

var (
	path string
	arch int
	opts ssce.Options
	out  string
)

func init() {
	flag.StringVar(&path, "i", "", "input shellcode file path")
	flag.IntVar(&arch, "arch", 64, "set architecture")
	flag.IntVar(&opts.NumIterator, "iter", 0, "set the number of the iterator")
	flag.IntVar(&opts.NumTailInst, "tail", 0, "set the number of the garbage inst at tail")
	flag.BoolVar(&opts.MinifyMode, "minify", false, "use minify mode, not recommend")
	flag.BoolVar(&opts.SaveContext, "safe", false, "save and restore context after call shellcode")
	flag.BoolVar(&opts.EraseInst, "erase", false, "erase shellcode after call it")
	flag.BoolVar(&opts.NoIterator, "no-iter", false, "no iterator, not recommend")
	flag.BoolVar(&opts.NoGarbage, "no-garbage", false, "no garbage, not recommend")
	flag.StringVar(&out, "o", "", "set output shellcode file path")
	flag.Parse()
}

func main() {
	if path == "" {
		flag.Usage()
		return
	}

	fmt.Printf("read input shellcode from \"%s\"\n", path)
	shellcode, err := os.ReadFile(path)
	checkError(err)
	fmt.Println("raw shellcode size:", len(shellcode))

	encoder := ssce.NewEncoder()
	shellcode, err = encoder.Encode(shellcode, arch, &opts)
	checkError(err)
	fmt.Println("encoded shellcode size:", len(shellcode))

	if out == "" {
		switch arch {
		case 32:
			out = "output_x86.bin"
		case 64:
			out = "output_x64.bin"
		}
	}
	fmt.Printf("write output shellcode to \"%s\"\n", out)
	err = os.WriteFile(out, shellcode, 0600)
	checkError(err)

	err = encoder.Close()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
