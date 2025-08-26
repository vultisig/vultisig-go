package libhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"
)

func Call[T any](
	ctx context.Context,
	method, url string,
	headers map[string]string,
	body any,
	query map[string]string,
) (T, error) {
	var reqBodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return *new(T), fmt.Errorf("failed to marshal request json: %w", err)
		}
		reqBodyBytes = b
	}

	var q string
	if query != nil {
		qurl := stdurl.Values{}
		for k, v := range query {
			qurl.Set(k, v)
		}
		q = "?" + qurl.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, url+q, bytes.NewReader(reqBodyBytes))
	if err != nil {
		return *new(T), fmt.Errorf("failed to build http request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return *new(T), fmt.Errorf("failed to make http call: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return *new(T), fmt.Errorf("failed to read response body: %w", err)
	}
	// Treat any 2xx as success
	if res.StatusCode < http.StatusOK || res.StatusCode >= 300 {
		return *new(T), fmt.Errorf(
			"failed to get successful response: status_code: %d, res_body: %s",
			res.StatusCode,
			string(bodyBytes),
		)
	}
	// Handle responses with no content gracefully
	if len(bodyBytes) == 0 {
		var zero T
		return zero, nil
	}

	// when no-JSON response is expected
	var zero T
	switch any(zero).(type) {
	case string:
		return any(string(bodyBytes)).(T), nil
	case nil:
		return zero, nil
	}

	var r T
	err = json.Unmarshal(bodyBytes, &r)
	if err != nil {
		return *new(T), fmt.Errorf("failed to unmarshal response json: %w", err)
	}

	return r, nil
}
