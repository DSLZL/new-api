package service

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/stretchr/testify/require"
)

func TestDecodeUrlImageData_FailsWhenHeaderStaysBeyondProbeLimit(t *testing.T) {
	payload := buildJPEGWithCommentPadding(t, 70*1024)
	server := newImageServer(payload, "image/jpeg")
	defer server.Close()

	restore := setupImageDownloadTest(t, server.Client())
	defer restore()

	config, format, err := DecodeUrlImageData(server.URL)
	require.Error(t, err)
	require.Empty(t, format)
	require.Zero(t, config.Width)
	require.Zero(t, config.Height)
}

func TestDecodeUrlImageData_SucceedsAfterProbeWindowExpands(t *testing.T) {
	payload := buildJPEGWithCommentPadding(t, 12*1024)
	server := newImageServer(payload, "image/jpeg")
	defer server.Close()

	restore := setupImageDownloadTest(t, server.Client())
	defer restore()

	config, format, err := DecodeUrlImageData(server.URL)
	require.NoError(t, err)
	require.Equal(t, "jpeg", format)
	require.Equal(t, 1, config.Width)
	require.Equal(t, 1, config.Height)
}

func TestDecodeUrlImageData_PropagatesReadError(t *testing.T) {
	expectedErr := errors.New("boom")
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"image/jpeg"}},
				Body: &erroringReadCloser{
					data: bytes.Repeat([]byte{0}, 256),
					err:  expectedErr,
				},
			}, nil
		}),
	}

	restore := setupImageDownloadTest(t, client)
	defer restore()

	_, _, err := DecodeUrlImageData("http://example.com/image.jpg")
	require.Error(t, err)
	require.ErrorIs(t, err, expectedErr)
	require.Contains(t, err.Error(), "failed to read image data")
}

func setupImageDownloadTest(t *testing.T, client *http.Client) func() {
	t.Helper()

	originalClient := httpClient
	originalWorkerURL := system_setting.WorkerUrl
	originalFetchSetting := *system_setting.GetFetchSetting()

	httpClient = client
	system_setting.WorkerUrl = ""
	fetchSetting := system_setting.GetFetchSetting()
	fetchSetting.EnableSSRFProtection = false

	return func() {
		httpClient = originalClient
		system_setting.WorkerUrl = originalWorkerURL
		*system_setting.GetFetchSetting() = originalFetchSetting
	}
}

func newImageServer(payload []byte, contentType string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(payload)
	}))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type erroringReadCloser struct {
	data []byte
	err  error
	done bool
}

func (r *erroringReadCloser) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), r.err
}

func (r *erroringReadCloser) Close() error {
	return nil
}

func buildJPEGWithCommentPadding(t *testing.T, padding int) []byte {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})

	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, nil))

	base := buf.Bytes()
	require.GreaterOrEqual(t, len(base), 2)

	padded := make([]byte, 0, len(base)+padding+padding/65533*4)
	padded = append(padded, base[:2]...)

	remaining := padding
	for remaining > 0 {
		chunk := min(remaining, 65533)
		segmentLength := chunk + 2
		padded = append(padded, 0xFF, 0xFE, byte(segmentLength>>8), byte(segmentLength))
		padded = append(padded, bytes.Repeat([]byte{0}, chunk)...)
		remaining -= chunk
	}

	padded = append(padded, base[2:]...)
	return padded
}
