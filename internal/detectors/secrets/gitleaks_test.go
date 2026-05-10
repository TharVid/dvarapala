package secrets

import (
	"context"
	"strings"
	"testing"
)

func TestDetectorFindsAWSKey(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	// Modern gitleaks ignores anything containing "EXAMPLE" as a stop word,
	// so we use a realistically-shaped key without it.
	content := `aws_access_key_id = AKIAQYLPMN5HABCDEFGH
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYabc123def456ghi7`
	hits, err := d.Detect(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one finding for AWS keys")
	}
	for _, h := range hits {
		if h.Detector != Name {
			t.Errorf("Detector field = %q, want %q", h.Detector, Name)
		}
		if h.RuleID == "" {
			t.Error("expected non-empty RuleID")
		}
	}
}

func TestDetectorIgnoresBenign(t *testing.T) {
	d, _ := New()
	hits, _ := d.Detect(context.Background(), "hello world\nthis is fine")
	if len(hits) != 0 {
		t.Errorf("got %d findings on benign content: %+v", len(hits), hits)
	}
}

func TestDetectorFindsPrivateKey(t *testing.T) {
	d, _ := New()
	// Modern gitleaks's private-key rule needs sufficient base64 body to
	// avoid false positives on examples; provide a few realistic lines.
	pk := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtIMDOwxMlpVafm0jwobaB2c7bBN3ZHfo7Jo4l3ay5BKH5x9C
Iu2QbDUC4xnhq5CeSlImD8q/3KEwGZ5cSL1FSr2qm4PjFZgZ2y1cUu+BAwiSJWoS
3l5sYqyzWqmPIwWqx8lYg+yWdJ7s8nEs0uACE4QTdZIBWWrBrwIDAQAB
-----END RSA PRIVATE KEY-----`
	hits, _ := d.Detect(context.Background(), pk)
	if len(hits) == 0 {
		t.Fatal("expected RSA private key to be flagged")
	}
	if !strings.Contains(strings.ToLower(hits[0].RuleID), "private") {
		t.Logf("note: rule id %q (gitleaks rule names vary by version)", hits[0].RuleID)
	}
}
