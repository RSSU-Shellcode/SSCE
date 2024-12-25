package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/RSSU-Shellcode/SSCE"
)

var (
	arch   int
	opts   ssce.Options
	hexIn  bool
	hexOut bool
	in     string
	out    string
)

func init() {
	flag.IntVar(&arch, "arch", 64, "set the architecture")
	flag.IntVar(&opts.NumIterator, "iter", 0, "set the number of the iterator")
	flag.IntVar(&opts.NumTailInst, "tail", 0, "set the number of the garbage inst at tail")
	flag.BoolVar(&opts.MinifyMode, "minify", false, "use minify mode, not recommend")
	flag.BoolVar(&opts.SaveContext, "safe", false, "save and restore context after call shellcode")
	flag.BoolVar(&opts.EraseInst, "erase", false, "erase shellcode after call it")
	flag.BoolVar(&opts.NoIterator, "no-iter", false, "no iterator, not recommend")
	flag.BoolVar(&opts.NoGarbage, "no-garbage", false, "no garbage, not recommend")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for encoder")
	flag.BoolVar(&opts.TrimSeed, "trim-seed", false, "trim the seed at the tail of output")
	flag.StringVar(&opts.X86MiniDecoder, "x86-md", "", "specify the x86 mini decoder template file path")
	flag.StringVar(&opts.X64MiniDecoder, "x64-md", "", "specify the x64 mini decoder template file path")
	flag.StringVar(&opts.X86Loader, "x86-ldr", "", "specify the x86 loader template file path")
	flag.StringVar(&opts.X64Loader, "x64-ldr", "", "specify the x64 loader template file path")
	flag.BoolVar(&hexIn, "hex-in", false, "input shellcode with hex format")
	flag.BoolVar(&hexOut, "hex-out", false, "output shellcode with hex format")
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

	opts.X86MiniDecoder = loadSourceTemplate(opts.X86MiniDecoder)
	opts.X64MiniDecoder = loadSourceTemplate(opts.X64MiniDecoder)
	opts.X86Loader = loadSourceTemplate(opts.X86Loader)
	opts.X64Loader = loadSourceTemplate(opts.X64Loader)

	encoder := ssce.NewEncoder(0)
	if opts.RandSeed == 0 {
		fmt.Println("random seed:", encoder.Seed())
	}

	shellcode, err := os.ReadFile(in) // #nosec
	checkError(err)
	fmt.Printf("read input shellcode from \"%s\"\n", in)
	if hexIn {
		shellcode, err = hex.DecodeString(string(shellcode))
		checkError(err)
	}
	fmt.Println("raw shellcode size:", len(shellcode))

	shellcode, err = encoder.Encode(shellcode, arch, &opts)
	checkError(err)
	fmt.Println("encoded shellcode size:", len(shellcode))

	if hexOut {
		shellcode = []byte(hex.EncodeToString(shellcode))
	}
	err = os.WriteFile(out, shellcode, 0600)
	checkError(err)
	fmt.Printf("write output shellcode to \"%s\"\n", out)

	err = encoder.Close()
	checkError(err)
}

func loadSourceTemplate(path string) string {
	if path == "" {
		return ""
	}
	asm, err := os.ReadFile(path) // #nosec
	checkError(err)
	return string(asm)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
