package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - No Scheme",
			headers: http.Header{
				"Authorization": []string{"some-random-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Wrong Scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer some-random-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotErr != nil && tt.expectedError == nil {
				t.Errorf("expected no error, got %v", gotErr)
				return
			}

			if gotErr == nil && tt.expectedError != nil {
				t.Errorf("expected error %v, got none", tt.expectedError)
				return
			}

			if gotErr != nil && tt.expectedError != nil && gotErr.Error() != tt.expectedError.Error() {
				t.Errorf("expected error %v, got %v", tt.expectedError, gotErr)
				return
			}

			if gotKey != tt.expectedKey {
				t.Errorf("expected API key %v, got %v", tt.expectedKey, gotKey)
			}
		})
	}
}
