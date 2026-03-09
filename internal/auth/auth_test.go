package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		expectedKey   string
		expectedError bool
		errorMessage  string
	}{
		{
			name:          "valid API key",
			header:        "ApiKey test-key-123",
			expectedKey:   "test-key-123",
			expectedError: false,
		},
		{
			name:          "no authorization header",
			header:        "",
			expectedKey:   "",
			expectedError: true,
			errorMessage:  "no authorization header included",
		},
		{
			name:          "malformed header - no space",
			header:        "ApiKeytest-key-123",
			expectedKey:   "",
			expectedError: true,
			errorMessage:  "malformed authorization header",
		},
		{
			name:          "malformed header - wrong prefix",
			header:        "Bearer test-key-123",
			expectedKey:   "",
			expectedError: true,
			errorMessage:  "malformed authorization header",
		},
		{
			name:          "malformed header - only prefix",
			header:        "ApiKey",
			expectedKey:   "",
			expectedError: true,
			errorMessage:  "malformed authorization header",
		},
		{
			name:          "valid API key with special characters",
			header:        "ApiKey sk_live_abc123-def456_xyz789",
			expectedKey:   "sk_live_abc123-def456_xyz789",
			expectedError: false,
		},
		{
			name:          "valid API key with extra spaces",
			header:        "ApiKey key-with-spaces  trailing",
			expectedKey:   "key-with-spaces",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			key, err := GetAPIKey(headers)

			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if tt.errorMessage != "" && err.Error() != tt.errorMessage {
					t.Errorf("expected error message %q, got %q", tt.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if key != tt.expectedKey {
					t.Errorf("expected key %q, got %q", tt.expectedKey, key)
				}
			}
		})
	}
}

func TestErrNoAuthHeaderIncluded(t *testing.T) {
	if ErrNoAuthHeaderIncluded == nil {
		t.Errorf("ErrNoAuthHeaderIncluded should not be nil")
	}

	expectedMessage := "no authorization header included"
	if ErrNoAuthHeaderIncluded.Error() != expectedMessage {
		t.Errorf("expected error message %q, got %q", expectedMessage, ErrNoAuthHeaderIncluded.Error())
	}
}
