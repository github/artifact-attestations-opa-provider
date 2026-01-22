package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidTrustDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid cases
		{
			name:     "lowercase letters only",
			input:    "example",
			expected: true,
		},
		{
			name:     "uppercase letters only",
			input:    "EXAMPLE",
			expected: true,
		},
		{
			name:     "mixed case letters",
			input:    "ExAmPlE",
			expected: true,
		},
		{
			name:     "numbers only",
			input:    "12345",
			expected: true,
		},
		{
			name:     "alphanumeric",
			input:    "example123",
			expected: true,
		},
		{
			name:     "hyphen in middle",
			input:    "my-domain",
			expected: true,
		},
		{
			name:     "multiple hyphens in middle",
			input:    "my-trust-domain",
			expected: true,
		},
		{
			name:     "single character",
			input:    "a",
			expected: true,
		},
		{
			name:     "max length 63 characters",
			input:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: true,
		},
		{
			name:     "dotcom special case handled elsewhere",
			input:    "dotcom",
			expected: true,
		},

		// Invalid cases
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "exceeds max length 64 characters",
			input:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: false,
		},
		{
			name:     "starts with hyphen",
			input:    "-example",
			expected: false,
		},
		{
			name:     "ends with hyphen",
			input:    "example-",
			expected: false,
		},
		{
			name:     "only hyphen",
			input:    "-",
			expected: false,
		},
		{
			name:     "contains dot",
			input:    "my.domain",
			expected: false,
		},
		{
			name:     "contains underscore",
			input:    "my_domain",
			expected: false,
		},
		{
			name:     "contains space",
			input:    "my domain",
			expected: false,
		},
		{
			name:     "contains slash",
			input:    "my/domain",
			expected: false,
		},
		{
			name:     "contains special characters",
			input:    "my@domain!",
			expected: false,
		},
		{
			name:     "contains unicode",
			input:    "domäin",
			expected: false,
		},
		{
			name:     "two character with hyphen only",
			input:    "a-",
			expected: false,
		},
		{
			name:     "two character starting with hyphen",
			input:    "-a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validTrustDomain(tt.input)
			assert.Equal(t, tt.expected, result, "validTrustDomain(%q) should be %v", tt.input, tt.expected)
		})
	}
}
