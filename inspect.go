package ssce

import (
	"fmt"
)

// InspectJunkCodeTemplate is used to test junk code template.
func InspectJunkCodeTemplate(arch int, src string) (string, []byte, error) {
	encoder := NewEncoder()
	encoder.arch = arch
	encoder.opts = new(Options)
	err := encoder.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := encoder.buildJunkCode(src)
	if err != nil {
		return "", nil, err
	}
	inst, err := encoder.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble junk code: %s", err)
	}
	return asm, inst, nil
}
