package ssce

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestInspectMiniDecoderTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		asm, inst, err := InspectMiniDecoderTemplate(32, defaultMiniDecoderX86)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		asm, inst, err := InspectMiniDecoderTemplate(64, defaultMiniDecoderX64)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})
}

func TestInspectLoaderTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(32, defaultLoaderX86)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(64, defaultLoaderX64)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})
}

func TestInspectJunkCodeTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, src := range defaultJunkCodeX86 {
			asm, inst, err := InspectJunkCodeTemplate(32, src)
			require.NoError(t, err)
			fmt.Println(asm)
			spew.Dump(inst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, src := range defaultJunkCodeX64 {
			asm, inst, err := InspectJunkCodeTemplate(64, src)
			require.NoError(t, err)
			fmt.Println(asm)
			spew.Dump(inst)
		}
	})
}
