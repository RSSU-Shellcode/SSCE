package ssce

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGarbageJumpShort(t *testing.T) {
	encoder := NewEncoder(1)
	encoder.opts = new(Options)

	for i := 0; i < 1000; i++ {
		size := len(encoder.garbageJumpShort(2, 5))
		require.True(t, size >= 2+2 && size <= 5+2)
	}

	err := encoder.Close()
	require.NoError(t, err)
}

func TestGarbageTemplate(t *testing.T) {
	encoder := NewEncoder(1)
	encoder.opts = new(Options)

	for i := 0; i < 1000; i++ {
		data := encoder.garbageTemplate()
		require.NotNil(t, data)
	}

	err := encoder.Close()
	require.NoError(t, err)
}
