package main

import (
	"context"
	"strings"
	"testing"
)

// -- Exit codes + error contract ---------------------------------------------------

func TestWhoamiWithoutCredentialsPrintsHumanErrorAndExits1(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"whoami"})
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	errOut := tio.err.String()
	if !strings.HasPrefix(errOut, "error: ") {
		t.Errorf("stderr = %q, want a one-line `error: ...` message", errOut)
	}
	if !strings.Contains(errOut, "knoxcall login") {
		t.Errorf("stderr = %q, want the re-login hint", errOut)
	}
	if strings.Contains(errOut, "goroutine") || strings.Contains(errOut, "panic") {
		t.Errorf("stderr contains a stack trace:\n%s", errOut)
	}
}

func TestLogoutExitZero(t *testing.T) {
	isolateEnv(t)
	a, _ := newTestApp(t)
	if rc := a.run(context.Background(), []string{"logout"}); rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
}

func TestNoCommandExitsTwo(t *testing.T) {
	a, tio := newTestApp(t)
	if rc := a.run(context.Background(), nil); rc != 2 {
		t.Fatalf("exit = %d, want 2", rc)
	}
	if !strings.Contains(tio.err.String(), "usage: knoxcall") {
		t.Errorf("stderr = %q, want the usage text", tio.err.String())
	}
}

func TestUnknownCommandExitsTwo(t *testing.T) {
	a, tio := newTestApp(t)
	if rc := a.run(context.Background(), []string{"frobnicate"}); rc != 2 {
		t.Fatalf("exit = %d, want 2", rc)
	}
	errOut := tio.err.String()
	if !strings.Contains(errOut, "frobnicate") || !strings.Contains(errOut, "usage: knoxcall") {
		t.Errorf("stderr = %q, want the unknown command named plus usage", errOut)
	}
}

func TestUnknownFlagExitsTwo(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	if rc := a.run(context.Background(), []string{"login", "--bogus"}); rc != 2 {
		t.Fatalf("exit = %d, want 2", rc)
	}
	errOut := tio.err.String()
	if !strings.Contains(errOut, "bogus") || !strings.Contains(errOut, "usage: knoxcall login") {
		t.Errorf("stderr = %q, want the bad flag named plus login usage", errOut)
	}
}

func TestHelpExitsZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"root", []string{"--help"}, "{login,logout,whoami,init,ai}"},
		{"login", []string{"login", "-h"}, "--no-browser"},
		{"logout", []string{"logout", "--help"}, "revoke and remove stored credentials"},
		{"whoami", []string{"whoami", "-h"}, "show the signed-in tenant"},
		{"init", []string{"init", "--help"}, "does NOT provision a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, tio := newTestApp(t)
			if rc := a.run(context.Background(), tc.argv); rc != 0 {
				t.Fatalf("exit = %d, want 0", rc)
			}
			if !strings.Contains(tio.out.String(), tc.want) {
				t.Errorf("stdout = %q, want it to mention %q", tio.out.String(), tc.want)
			}
			if tio.err.Len() != 0 {
				t.Errorf("stderr = %q, want help on stdout only", tio.err.String())
			}
		})
	}
}

func TestInterruptPrintsAborted(t *testing.T) {
	isolateEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate Ctrl-C via signal.NotifyContext

	a, tio := newTestApp(t)
	rc := a.run(ctx, []string{"login", "--device", "--base-url", "http://127.0.0.1:9"})
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	errOut := tio.err.String()
	if strings.TrimSpace(errOut) != "aborted" {
		t.Errorf("stderr = %q, want exactly `aborted`", errOut)
	}
}
