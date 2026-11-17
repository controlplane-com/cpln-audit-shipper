package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestOneClientServesConcurrentCallers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	c := &Client{Service: "test"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Do(context.Background(), func(ctx context.Context) (*http.Request, error) {
				return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
