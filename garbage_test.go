package ssce

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGarbageJumpShort(t *testing.T) {
	encoder := NewEncoder(0)
	encoder.opts = new(Options)

	t.Run("x86", func(t *testing.T) {
		encoder.arch = 32

		for i := 0; i < 1000; i++ {
			size := len(encoder.garbageJumpShort(2, 5))
			require.True(t, size >= 2+2 && size <= 5+2)
		}
	})

	t.Run("x64", func(t *testing.T) {
		encoder.arch = 64

		for i := 0; i < 1000; i++ {
			size := len(encoder.garbageJumpShort(2, 5))
			require.True(t, size >= 2+2 && size <= 5+2)
		}
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestGarbageTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		encoder := NewEncoder(0)
		encoder.arch = 32
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := encoder.garbageTemplate()
			require.NotEmpty(t, data)
		}

		err = encoder.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		encoder := NewEncoder(0)
		encoder.arch = 64
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := encoder.garbageTemplate()
			require.NotEmpty(t, data)
		}

		err = encoder.Close()
		require.NoError(t, err)
	})
}
