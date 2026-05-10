package pii

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectorParsesPresidioResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req presidioRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if !strings.Contains(req.Text, "alice@example.com") {
			t.Errorf("request text missing email; got %q", req.Text)
		}
		// Mock response with a fake email finding.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":12,"end":29,"score":0.95}]`))
	}))
	defer srv.Close()

	d := New(srv.URL, WithThreshold(0.5))
	hits, err := d.Detect(context.Background(), "contact me: alice@example.com tomorrow")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("got %d findings, want 1", len(hits))
	}
	h := hits[0]
	if h.Detector != Name {
		t.Errorf("Detector = %q, want %q", h.Detector, Name)
	}
	if h.RuleID != "EMAIL_ADDRESS" {
		t.Errorf("RuleID = %q", h.RuleID)
	}
	if h.Match != "alice@example.com" {
		t.Errorf("Match = %q", h.Match)
	}
	if h.Score < 0.9 {
		t.Errorf("Score = %v", h.Score)
	}
}

func TestDetectorReturnsErrorWhenSidecarDown(t *testing.T) {
	d := New("http://127.0.0.1:1") // unroutable
	_, err := d.Detect(context.Background(), "irrelevant")
	if err == nil {
		t.Fatal("expected error when sidecar unreachable")
	}
}

func TestDetectorEmptyContentNoOp(t *testing.T) {
	d := New("http://127.0.0.1:1")
	hits, err := d.Detect(context.Background(), "")
	if err != nil || hits != nil {
		t.Errorf("got hits=%v err=%v; want nil/nil", hits, err)
	}
}

func TestDetectorBadStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := New(srv.URL)
	_, err := d.Detect(context.Background(), "anything")
	if err == nil {
		t.Fatal("expected error on 500")
	}
}
