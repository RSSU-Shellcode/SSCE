package ssce

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompressRatio(t *testing.T) {
	t.Run("32", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x00}, 256*1024)
		key := make([]byte, 32)

		for i := 0; i < 1000; i++ {
			_, err := rand.Read(key)
			require.NoError(t, err)
			cipher := encrypt32(data, key)
			require.NoError(t, err)

			buf := bytes.NewBuffer(make([]byte, 0, 256*1024))
			w, err := flate.NewWriter(buf, flate.BestCompression)
			require.NoError(t, err)
			_, err = w.Write(cipher)
			require.NoError(t, err)
			err = w.Close()
			require.NoError(t, err)

			expected := len(cipher) * 98 / 100
			require.Greaterf(t, buf.Len(), expected, "bad compress ratio at %d\n", i)
		}
	})

	t.Run("64", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x00}, 256*1024)
		key := make([]byte, 32)

		for i := 0; i < 1000; i++ {
			_, err := rand.Read(key)
			require.NoError(t, err)
			cipher := encrypt64(data, key)
			require.NoError(t, err)

			buf := bytes.NewBuffer(make([]byte, 0, 256*1024))
			w, err := flate.NewWriter(buf, flate.BestCompression)
			require.NoError(t, err)
			_, err = w.Write(cipher)
			require.NoError(t, err)
			err = w.Close()
			require.NoError(t, err)

			expected := len(cipher) * 98 / 100
			require.Greaterf(t, buf.Len(), expected, "bad compress ratio at %d\n", i)
		}
	})
}
