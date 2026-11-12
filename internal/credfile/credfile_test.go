package credfile

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// First-ever login: ~/.knoxcall/ does not exist yet. O_CREATE on the lock
// path used to fail with a missing-parent error that tryAcquire swallowed as
// contention — spinning for the full timeout. Regression: Acquire must
// create the parent and succeed immediately.
func TestLockAcquiresWhenParentDirMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh", "nested", "credentials.json")
	lock := &FileLock{LockPath: path + ".lock", Timeout: 2 * time.Second, RetryInterval: 100 * time.Millisecond, StaleAfter: 30 * time.Second}

	start := time.Now()
	if err := lock.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire in fresh dir: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("acquire spun for %v — parent dir not pre-created", elapsed)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("lock file missing while held: %v", err)
	}
	lock.Release()
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lock file not removed on release: %v", err)
	}

	// The full first-login write path works in the fresh dir too.
	if err := WriteDocument(path, map[string]any{"version": 1, "profiles": map[string]any{"default": map[string]any{"tenant": "acme"}}}); err != nil {
		t.Fatalf("write document: %v", err)
	}
}

// Ownership-aware release: after this instance's (apparently stale) lock is
// broken and re-taken by another process, Release must NOT delete the lock it
// no longer owns — deleting it would admit a concurrent single-use refresh.
func TestReleaseDoesNotDeleteLockOwnedByAnotherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	lock := NewLock(path)
	if err := lock.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Simulate another process breaking our lock and taking it: the on-disk
	// content is now someone else's, not the token we wrote at acquire.
	const otherContent = "777 123456789\n"
	if err := os.WriteFile(lock.LockPath, []byte(otherContent), 0o600); err != nil {
		t.Fatalf("overwrite lock: %v", err)
	}

	lock.Release()

	content, err := os.ReadFile(lock.LockPath)
	if err != nil {
		t.Fatalf("Release deleted a lock owned by another process: %v", err)
	}
	if string(content) != otherContent {
		t.Fatalf("lock content = %q, want the other owner's content left untouched", content)
	}
}

// The happy path still holds: Release removes a lock this instance owns.
func TestReleaseDeletesOwnLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	lock := NewLock(path)
	if err := lock.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	lock.Release()
	if _, err := os.Stat(lock.LockPath); !os.IsNotExist(err) {
		t.Fatalf("own lock not removed on release (stat err = %v)", err)
	}
}

// Ownership-aware stale-break: if the lock's content changes after it was
// observed stale (another process released + re-acquired), the break must not
// unlink the now-live lock.
func TestBreakStaleDoesNotDeleteLockWhoseContentChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	lock := NewLock(path)

	const liveContent = "222 2\n"
	if err := os.WriteFile(lock.LockPath, []byte(liveContent), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	// removeIfUnchanged is handed the OLD content it saw as stale; the disk now
	// holds a different owner's content, so it must refuse to unlink.
	if lock.removeIfUnchanged("111 1\n") {
		t.Fatalf("removeIfUnchanged deleted a lock whose content changed under it")
	}
	content, err := os.ReadFile(lock.LockPath)
	if err != nil {
		t.Fatalf("live lock was deleted: %v", err)
	}
	if string(content) != liveContent {
		t.Fatalf("lock content = %q, want the live lock left untouched", content)
	}
}

// captureWarnings swaps the package warn writer for a buffer and clears the
// once-per-process dedup, restoring both when the (sub)test ends.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := warnWriter
	buf := &bytes.Buffer{}
	warnWriter = buf
	resetPermsWarnedForTests()
	t.Cleanup(func() {
		warnWriter = orig
		resetPermsWarnedForTests()
	})
	return buf
}

// A credentials file that is group/other-accessible (0o644) warns to chmod it
// on read; a locked-down 0o600 file is silent. POSIX only — the mode bits are
// advisory on Windows, so the check is skipped there. PARITY §15.
func TestLoosePermissionsWarnOnRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only: file mode bits are advisory on Windows")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	doc := map[string]any{
		"version":  1,
		"profiles": map[string]any{"default": map[string]any{"tenant": "acme"}},
	}
	if err := WriteDocument(path, doc); err != nil {
		t.Fatalf("WriteDocument: %v", err)
	}

	t.Run("loose 0644 warns once", func(t *testing.T) {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("chmod 0644: %v", err)
		}
		buf := captureWarnings(t)
		// The read still succeeds — the warning never changes behavior.
		if ReadProfile(path, "default") == nil {
			t.Fatalf("ReadProfile returned nil for a valid file")
		}
		out := buf.String()
		if !strings.Contains(out, "chmod 600") || !strings.Contains(out, "KNOXCALL_CREDENTIALS_FILE_PERMS") {
			t.Fatalf("expected a chmod-600 permission warning, got %q", out)
		}
		// A second read must not re-warn (once per process).
		if ReadProfile(path, "default") == nil {
			t.Fatalf("second ReadProfile returned nil")
		}
		if n := strings.Count(buf.String(), "KNOXCALL_CREDENTIALS_FILE_PERMS"); n != 1 {
			t.Fatalf("permission warning fired %d times, want exactly 1", n)
		}
	})

	t.Run("tight 0600 is silent", func(t *testing.T) {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("chmod 0600: %v", err)
		}
		buf := captureWarnings(t)
		if ReadProfile(path, "default") == nil {
			t.Fatalf("ReadProfile returned nil for a valid file")
		}
		if buf.Len() != 0 {
			t.Fatalf("a 0600 file must not warn, got %q", buf.String())
		}
	})
}

// End-to-end: a genuinely stale lock (old mtime, unchanged content) is still
// broken so Acquire succeeds promptly.
func TestStaleLockWithUnchangedContentIsBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	lock := NewLock(path)
	if err := os.WriteFile(lock.LockPath, []byte("111 1\n"), 0o600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}
	old := time.Now().Add(-2 * lock.StaleAfter)
	if err := os.Chtimes(lock.LockPath, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	start := time.Now()
	if err := lock.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire over a stale lock: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("acquire spun instead of breaking the stale lock")
	}
	lock.Release()
	if _, err := os.Stat(lock.LockPath); !os.IsNotExist(err) {
		t.Fatalf("lock not removed after acquire+release (stat err = %v)", err)
	}
}
