package assertion

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBody(t *testing.T) {
	t.Run("reads body and allows re-read", func(t *testing.T) {
		body := "hello world"
		r := &http.Request{
			Body: io.NopCloser(strings.NewReader(body)),
		}

		data, err := readBody(r)
		require.NoError(t, err)
		assert.Equal(t, []byte(body), data)

		// Body should still be readable after readBody.
		reread, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, []byte(body), reread)
	})

	t.Run("nil body returns nil", func(t *testing.T) {
		r := &http.Request{Body: nil}

		data, err := readBody(r)
		require.NoError(t, err)
		assert.Nil(t, data)
	})

	t.Run("empty body returns empty slice", func(t *testing.T) {
		r := &http.Request{
			Body: io.NopCloser(strings.NewReader("")),
		}

		data, err := readBody(r)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, data)
	})
}
