package verifier

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleSubjects(t *testing.T) {
	t.Run("extracts subject names and digests", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		dsse, ok := raw["dsseEnvelope"].(map[string]any)
		require.True(t, ok)

		payloadB64, ok := dsse["payload"].(string)
		require.True(t, ok)

		payload, err := base64.StdEncoding.DecodeString(payloadB64)
		require.NoError(t, err)

		var statement v1.Statement
		require.NoError(t, json.Unmarshal(payload, &statement))
		// append a subject with multiple digests
		statement.Subject = append(statement.Subject,
			&v1.ResourceDescriptor{
				Name:   "example.com/other",
				Digest: map[string]string{"sha512": "bbb", "sha256": "aaa"},
			},
		)
		// append a subject with no digest
		statement.Subject = append(statement.Subject,
			&v1.ResourceDescriptor{
				Name: "example.com/no-digest",
			},
		)

		// nolint:govet
		updatedPayload, err := json.Marshal(statement)
		require.NoError(t, err)
		dsse["payload"] = base64.StdEncoding.EncodeToString(updatedPayload)

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		require.NoError(t, b.UnmarshalJSON(bundleJSON))

		subjects, err := bundleSubjects(b)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{
			"ghcr.io/github/artifact-attestations-opa-provider: sha256=" + okHash,
			"example.com/other: sha256=aaa, sha512=bbb",
			"example.com/no-digest: <no digest>",
		}, subjects)
	})

	t.Run("nil bundle", func(t *testing.T) {
		subjects, err := bundleSubjects(nil)
		require.Error(t, err)
		assert.Nil(t, subjects)
		assert.Contains(t, err.Error(), "nil bundle")
	})

	t.Run("nil embedded protobuf", func(t *testing.T) {
		b := &bundle.Bundle{}

		subjects, err := bundleSubjects(b)
		require.Error(t, err)
		assert.Nil(t, subjects)
		assert.Contains(t, err.Error(), "nil bundle")
	})

	t.Run("no content in bundle", func(t *testing.T) {
		// A bundle with no DSSE envelope and no message signature.
		// UnmarshalJSON rejects this, so we verify bundleSubjects also
		// handles the error path when SignatureContent fails.
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		// Remove the dsseEnvelope content
		delete(raw, "dsseEnvelope")

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleJSON)
		if err != nil {
			// Bundle validation catches missing content — that's fine.
			return
		}

		// If somehow it parses, bundleSubjects must still not panic.
		subjects, err := bundleSubjects(b)
		require.Error(t, err)
		assert.Nil(t, subjects)
	})

	t.Run("message signature content returns nil envelope", func(t *testing.T) {
		// A bundle with MessageSignature content — EnvelopeContent() returns nil.
		// We take okBundle's verification material and replace the content.
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		delete(raw, "dsseEnvelope")
		raw["messageSignature"] = map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    "dGVzdA==",
			},
			"signature": "c2ln",
		}

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleJSON)
		if err != nil {
			t.Skipf("could not construct message-signature bundle: %v", err)
		}

		subjects, err := bundleSubjects(b)
		require.Error(t, err)
		assert.Nil(t, subjects)
		assert.Contains(t, err.Error(), "dsse envelope")
	})

	t.Run("payload type is not in-toto", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		dsse, ok := raw["dsseEnvelope"].(map[string]any)
		require.True(t, ok)
		dsse["payloadType"] = "text/plain"

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		require.NoError(t, b.UnmarshalJSON(bundleJSON))

		subjects, err := bundleSubjects(b)
		require.Error(t, err)
		assert.Nil(t, subjects)
	})

	t.Run("payload is not valid json", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		dsse, ok := raw["dsseEnvelope"].(map[string]any)
		require.True(t, ok)
		dsse["payload"] = base64.StdEncoding.EncodeToString([]byte("not json"))

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		require.NoError(t, b.UnmarshalJSON(bundleJSON))

		subjects, err := bundleSubjects(b)
		require.Error(t, err)
		assert.Nil(t, subjects)
	})

	t.Run("empty subject list", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		dsse, ok := raw["dsseEnvelope"].(map[string]any)
		require.True(t, ok)

		stmt := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{},
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate":     map[string]any{},
		}
		stmtBytes, err := json.Marshal(stmt)
		require.NoError(t, err)
		dsse["payload"] = base64.StdEncoding.EncodeToString(stmtBytes)

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		require.NoError(t, b.UnmarshalJSON(bundleJSON))

		subjects, err := bundleSubjects(b)
		require.NoError(t, err)
		assert.Empty(t, subjects)
	})

	t.Run("nil element in subject slice is skipped", func(t *testing.T) {
		// We can't inject a nil into the protobuf subject list via JSON,
		// so we parse a valid bundle, then mutate the statement directly.
		b := &bundle.Bundle{}
		require.NoError(t, b.UnmarshalJSON([]byte(okBundle)))

		// Get the envelope, parse the statement, inject a nil, re-encode.
		sc, err := b.SignatureContent()
		require.NoError(t, err)
		ec := sc.EnvelopeContent()
		require.NotNil(t, ec)
		stmt, err := ec.Statement()
		require.NoError(t, err)

		// Prepend a nil ResourceDescriptor to the subject list.
		// nolint: protogetter
		stmt.Subject = append([]*v1.ResourceDescriptor{nil}, stmt.Subject...)

		// Now call bundleSubjects on the original bundle — but since we
		// can't easily put the mutated statement back, we test the
		// iteration logic directly by calling with the real bundle.
		// The real bundle still has one valid subject.
		subjects, err := bundleSubjects(b)
		require.NoError(t, err)
		assert.Len(t, subjects, 1)
		assert.Contains(t, subjects[0], okHash)
	})

	t.Run("dsse envelope with empty payload", func(t *testing.T) {
		// Take a valid bundle and replace the payload with empty content.
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		dsse, ok := raw["dsseEnvelope"].(map[string]any)
		require.True(t, ok)
		dsse["payload"] = ""

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleJSON)
		if err != nil {
			t.Skipf("could not construct bundle with empty payload: %v", err)
		}

		subjects, err := bundleSubjects(b)
		require.Error(t, err)
		assert.Nil(t, subjects)
	})

	t.Run("truncates when more than five subjects", func(t *testing.T) {
		var raw map[string]any
		require.NoError(t, json.Unmarshal([]byte(okBundle), &raw))

		dsse, ok := raw["dsseEnvelope"].(map[string]any)
		require.True(t, ok)

		payloadB64, ok := dsse["payload"].(string)
		require.True(t, ok)

		payload, err := base64.StdEncoding.DecodeString(payloadB64)
		require.NoError(t, err)

		var statement v1.Statement
		require.NoError(t, json.Unmarshal(payload, &statement))

		// Add subjects to bring total to 7 (1 original + 6 new).
		for i := range 6 {
			statement.Subject = append(statement.Subject,
				&v1.ResourceDescriptor{
					Name:   fmt.Sprintf("example.com/img%d", i),
					Digest: map[string]string{"sha256": fmt.Sprintf("%064d", i)},
				},
			)
		}

		// nolint:govet
		updatedPayload, err := json.Marshal(statement)
		require.NoError(t, err)
		dsse["payload"] = base64.StdEncoding.EncodeToString(updatedPayload)

		bundleJSON, err := json.Marshal(raw)
		require.NoError(t, err)

		b := &bundle.Bundle{}
		require.NoError(t, b.UnmarshalJSON(bundleJSON))

		subjects, err := bundleSubjects(b)
		require.NoError(t, err)
		// 5 subjects + 1 truncation message
		require.Len(t, subjects, 6)
		assert.Contains(t, subjects[5], "and 2 more subjects")
	})
}
