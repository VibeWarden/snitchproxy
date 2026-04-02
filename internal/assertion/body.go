package assertion

import (
	"bytes"
	"io"
	"net/http"
)

// readBody reads the request body and replaces it with a new reader
// so downstream handlers can still read it.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}
