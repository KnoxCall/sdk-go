package knoxcall

// The KNOXCALL_INTERCEPT off-grammar, driven by the CROSS-LANGUAGE fixture in
// sdk/fixtures/intercept-kill-switch.json (PARITY 21.1).
//
// Five SDKs hand-write this predicate and already agree character for
// character. A sixth spelling accepted here would be a kill switch that works
// in four SDKs and silently does nothing in the fifth -- the worst shape a kill
// switch can have, because the operator believes interception is off.
//
// The file is read from the monorepo path on purpose (the contract is the
// shared file, not a copy that could drift) and a missing file FAILS rather
// than skips: a skipped contract test reads as a pass.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type killSwitchFixture struct {
	Cases []killSwitchCase `json:"cases"`
}

type killSwitchCase struct {
	Name   string  `json:"name"`
	Value  *string `json:"value"`
	Expect bool    `json:"expect"`
}

func TestInterceptKillSwitchSharedFixture(t *testing.T) {
	path := filepath.Join("..", "..", "fixtures", "intercept-kill-switch.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fx killSwitchFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(fx.Cases) == 0 {
		t.Fatalf("%s has no cases", path)
	}

	sawTrue, sawFalse := false, false
	for _, c := range fx.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if c.Value == nil {
				os.Unsetenv("KNOXCALL_INTERCEPT")
			} else {
				t.Setenv("KNOXCALL_INTERCEPT", *c.Value)
			}
			if got := interceptKillSwitch(); got != c.Expect {
				t.Fatalf("KNOXCALL_INTERCEPT=%q: kill switch = %v, want %v", valueOf(c.Value), got, c.Expect)
			}
		})
		if c.Expect {
			sawTrue = true
		} else {
			sawFalse = true
		}
	}
	if !sawTrue || !sawFalse {
		t.Fatalf("the fixture must contain both verdicts (true=%v false=%v)", sawTrue, sawFalse)
	}
}

func valueOf(v *string) string {
	if v == nil {
		return "<absent>"
	}
	return *v
}
