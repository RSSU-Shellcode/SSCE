package ssce

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestSaveContext(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		encoder := NewEncoder(0)
		encoder.arch = 32
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		inst := encoder.saveContext()
		spew.Dump(inst)

		err = encoder.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		encoder := NewEncoder(0)
		encoder.arch = 64
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		inst := encoder.saveContext()
		spew.Dump(inst)

		err = encoder.Close()
		require.NoError(t, err)
	})
}

func TestRestoreContext(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		encoder := NewEncoder(0)
		encoder.arch = 32
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		encoder.saveContext()

		inst := encoder.restoreContext()
		spew.Dump(inst)

		err = encoder.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		encoder := NewEncoder(0)
		encoder.arch = 64
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		encoder.saveContext()

		inst := encoder.restoreContext()
		spew.Dump(inst)

		err = encoder.Close()
		require.NoError(t, err)
	})
}
