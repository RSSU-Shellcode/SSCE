package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/RSSU-Shellcode/SSCE"
)

var (
	seed int64
	arch int
	opts ssce.Options
	ih   bool
	oh   bool
	in   string
	out  string
)

func init() {
	flag.Int64Var(&seed, "seed", 0, "set the random seed")
	flag.IntVar(&arch, "arch", 64, "set the architecture")
	flag.IntVar(&opts.NumIterator, "iter", 0, "set the number of the iterator")
	flag.IntVar(&opts.NumTailInst, "tail", 0, "set the number of the garbage inst at tail")
	flag.BoolVar(&opts.MinifyMode, "minify", false, "use minify mode, not recommend")
	flag.BoolVar(&opts.SaveContext, "safe", false, "save and restore context after call shellcode")
	flag.BoolVar(&opts.EraseInst, "erase", false, "erase shellcode after call it")
	flag.BoolVar(&opts.NoIterator, "no-iter", false, "no iterator, not recommend")
	flag.BoolVar(&opts.NoGarbage, "no-garbage", false, "no garbage, not recommend")
	flag.BoolVar(&ih, "ih", false, "input shellcode with hex format")
	flag.BoolVar(&oh, "oh", false, "output shellcode with hex format")
	flag.StringVar(&in, "i", "", "set input shellcode file path")
	flag.StringVar(&out, "o", "", "set output shellcode file path")
	flag.Parse()
}

func main() {
	if in == "" {
		flag.Usage()
		return
	}
	if out == "" {
		switch arch {
		case 32:
			out = "output_x86.bin"
		case 64:
			out = "output_x64.bin"
		}
	}

	encoder := ssce.NewEncoder(seed)
	fmt.Println("random seed:", encoder.Seed())

	fmt.Printf("read input shellcode from \"%s\"\n", in)
	shellcode, err := os.ReadFile(in) // #nosec
	checkError(err)
	if ih {
		shellcode, err = hex.DecodeString(string(shellcode))
		checkError(err)
	}
	fmt.Println("raw shellcode size:", len(shellcode))

	shellcode, err = encoder.Encode(shellcode, arch, &opts)
	checkError(err)
	fmt.Println("encoded shellcode size:", len(shellcode))

	fmt.Printf("write output shellcode to \"%s\"\n", out)
	if oh {
		shellcode = []byte(hex.EncodeToString(shellcode))
	}
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
