package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "valid api key",
			headers:    http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey:    "my-secret-key",
			wantErr:    nil,
			wantErrMsg: "",
		},
		{
			name:       "missing authorization header",
			headers:    http.Header{},
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
			wantErrMsg: "",
		},
		{
			name:       "missing api key prefix",
			headers:    http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantKey:    "",
			wantErr:    nil,
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "incomplete authorization header",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantErr:    nil,
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				if tt.wantErrMsg == "" {
					t.Fatalf("GetAPIKey() unexpected error = %v", err)
				}
				if err.Error() != tt.wantErrMsg {
					t.Fatalf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErrMsg)
				}
			}

			if got != tt.wantKey {
				t.Fatalf("GetAPIKey() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}
