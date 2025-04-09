package ssce

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestSaveContext(t *testing.T) {
	encoder := NewEncoder(1)
	encoder.opts = new(Options)

	t.Run("x86", func(t *testing.T) {
		encoder.arch = 32

		inst := encoder.saveContext()
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		encoder.arch = 64

		inst := encoder.saveContext()
		spew.Dump(inst)
	})
}

func TestRestoreContext(t *testing.T) {
	encoder := NewEncoder(1)
	encoder.opts = new(Options)

	t.Run("x86", func(t *testing.T) {
		encoder.arch = 32
		encoder.saveContext()

		inst := encoder.restoreContext()
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		encoder.arch = 64
		encoder.saveContext()

		inst := encoder.restoreContext()
		spew.Dump(inst)
	})
}
