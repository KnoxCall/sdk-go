package knoxcall

// The route-mode refusal predicate, driven by the CROSS-LANGUAGE fixtures in
// sdk/fixtures/route-refusal.json (PARITY §21.1, "Refusal-driven refresh").
// Node is the reference; this file consumes the same cases unchanged.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type routeRefusalCase struct {
	Name    string            `json:"name"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Expect  struct {
		Refusal bool `json:"refusal"`
	} `json:"expect"`
}

func loadRouteRefusalFixture(t *testing.T) []routeRefusalCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "route-refusal.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f struct {
		Cases []routeRefusalCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f.Cases
}

func TestRouteRefusalSharedFixtures(t *testing.T) {
	cases := loadRouteRefusalFixture(t)
	if len(cases) < 10 {
		t.Fatalf("fixture has %d cases, want at least 10", len(cases))
	}
	sawTrue, sawFalse := false, false
	for _, c := range cases {
		if c.Expect.Refusal {
			sawTrue = true
		} else {
			sawFalse = true
		}
	}
	if !sawTrue || !sawFalse {
		t.Fatalf("fixture must answer in both directions (true=%v, false=%v)", sawTrue, sawFalse)
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			res := &http.Response{StatusCode: c.Status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(c.Body))}
			for k, v := range c.Headers {
				res.Header.Set(k, v)
			}
			if got := isRouteRefusal(res); got != c.Expect.Refusal {
				t.Fatalf("isRouteRefusal = %v, want %v", got, c.Expect.Refusal)
			}
			// The caller's body is untouched by the decision.
			body, err := io.ReadAll(res.Body)
			if err != nil || string(body) != c.Body {
				t.Fatalf("body after the decision = %q (err %v), want %q", body, err, c.Body)
			}
		})
	}
}
