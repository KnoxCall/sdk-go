// Package credfile implements the shared credentials file
// (~/.knoxcall/credentials.json) primitives — path/profile resolution,
// tolerant reads, atomic writes, the cross-process lock, and expiry
// formatting. It is consumed by both the knoxcall SDK package
// (StoredCredentials) and the cmd/knoxcall CLI; being under internal/ it is
// invisible outside this module, keeping the SDK's public API surface
// unchanged.
//
// Format, lock protocol, and refresh rules are cross-SDK identical (see
// ../../../PARITY.md §2); the Python SDK's auth/credentials_file.py is the
// reference implementation.
package credfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	// DefaultProfile is the profile used when neither an override nor
	// KNOXCALL_PROFILE selects one.
	DefaultProfile = "default"

	lockTimeout       = 10 * time.Second
	lockRetryInterval = 100 * time.Millisecond
	// lockStaleAfter must sit safely ABOVE the token-endpoint HTTP timeout
	// (the SDK's default http client is 30s). A refresh legitimately holds the
	// lock for the duration of its /oauth/token round-trip, so breaking the
	// lock any earlier could unlink a slow-but-live refresh's lock and let a
	// second process refresh concurrently — both would then rotate the
	// single-use refresh token and the server would family-revoke. 60s is a
	// 2x margin over the 30s request timeout.
	lockStaleAfter = 60 * time.Second
)

// -- Path / profile resolution --------------------------------------------------

// ResolvePath resolves the credentials file path: explicit override >
// KNOXCALL_CREDENTIALS_FILE > ~/.knoxcall/credentials.json. An unresolvable
// home directory yields "" — readers treat it as a missing file, so callers
// skip the provider silently.
func ResolvePath(override string) string {
	if override != "" {
		return override
	}
	if env := os.Getenv("KNOXCALL_CREDENTIALS_FILE"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".knoxcall", "credentials.json")
}

// ResolveProfile resolves the profile name: explicit override >
// KNOXCALL_PROFILE > "default".
func ResolveProfile(override string) string {
	if override != "" {
		return override
	}
	if env := os.Getenv("KNOXCALL_PROFILE"); env != "" {
		return env
	}
	return DefaultProfile
}

// -- One-time loose-permission warning --------------------------------------------

// warnWriter receives the one-time credentials-file permission warning.
// Swappable in tests; production writes to os.Stderr. This package cannot
// import the knoxcall package (that would be an import cycle — knoxcall imports
// credfile), so it carries its own once-per-process helper rather than sharing
// knoxcall.warnOnce.
var warnWriter io.Writer = os.Stderr

// permsWarned deduplicates the permission warning: it fires at most once per
// process (keyed by the warning code, matching node's warn-once-per-code
// semantics), so a program that reads the credentials file repeatedly does not
// spam stderr.
var permsWarned sync.Map

// resetPermsWarnedForTests clears the once-per-process dedup so the warning can
// be re-asserted. Test-only.
func resetPermsWarnedForTests() {
	permsWarned.Range(func(k, _ any) bool {
		permsWarned.Delete(k)
		return true
	})
}

// warnIfLoosePermissions warns ONCE if the credentials file at path — which
// holds a refresh token — is readable by group or other (mode & 0o077 != 0).
// POSIX only: on Windows the mode bits are advisory and confidentiality rests
// on the %USERPROFILE% ACL, so the check is skipped. Non-blocking and
// behavior-preserving (PARITY §15, mirrors node credentials-file.ts
// warnIfLoosePermissions).
func warnIfLoosePermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		return // missing/unreadable — nothing to warn about
	}
	mode := fi.Mode().Perm()
	if mode&0o077 == 0 {
		return
	}
	const code = "KNOXCALL_CREDENTIALS_FILE_PERMS"
	if _, loaded := permsWarned.LoadOrStore(code, struct{}{}); loaded {
		return
	}
	fmt.Fprintf(warnWriter,
		"knoxcall: warning: credentials file %s is accessible to group/other "+
			"(mode %03o) and holds a refresh token; restrict it: chmod 600 %s (%s)\n",
		path, mode, path, code)
}

// -- File primitives (tolerant reads, atomic writes) ------------------------------

// ReadDocument parses the whole file; nil on missing/malformed/unexpected
// shape (a document must be an object with a "profiles" object).
func ReadDocument(path string) map[string]any {
	if path == "" {
		return nil
	}
	warnIfLoosePermissions(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	if _, ok := doc["profiles"].(map[string]any); !ok {
		return nil
	}
	return doc
}

// ReadProfile returns one profile's record, or nil (missing file, malformed
// JSON, unknown profile).
func ReadProfile(path, profile string) map[string]any {
	doc := ReadDocument(path)
	if doc == nil {
		return nil
	}
	profiles := doc["profiles"].(map[string]any)
	record, ok := profiles[profile].(map[string]any)
	if !ok {
		return nil
	}
	// Copy so callers can mutate without aliasing the parsed document.
	out := make(map[string]any, len(record))
	for k, v := range record {
		out[k] = v
	}
	return out
}

// ProfileAvailable is the construction-time presence check: file exists AND
// the selected profile parses.
func ProfileAvailable(path, profile string) bool {
	return ReadProfile(path, profile) != nil
}

// WriteDocument writes the document atomically: temp file in the same
// directory → fsync → rename over the target. The directory is created 0700
// and the file chmod'd 0600 (best-effort — the mode bits are advisory on
// Windows). Never a partial write.
func WriteDocument(path string, doc map[string]any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	_ = os.Chmod(tmpPath, 0o600) // best-effort; advisory on Windows
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// WriteProfile merges one profile into the file (other profiles and unknown
// top-level keys untouched), atomically. Nil values are dropped from the
// record.
func WriteProfile(path, profile string, record map[string]any) error {
	doc := ReadDocument(path)
	if doc == nil {
		doc = map[string]any{"version": 1, "profiles": map[string]any{}}
	}
	if _, ok := doc["version"]; !ok {
		doc["version"] = 1
	}
	clean := make(map[string]any, len(record))
	for k, v := range record {
		if v != nil {
			clean[k] = v
		}
	}
	doc["profiles"].(map[string]any)[profile] = clean
	return WriteDocument(path, doc)
}

// RemoveProfile removes one profile; the file is deleted when it was the
// last one. Returns false when the file or profile did not exist.
func RemoveProfile(path, profile string) (bool, error) {
	doc := ReadDocument(path)
	if doc == nil {
		return false, nil
	}
	profiles := doc["profiles"].(map[string]any)
	if _, ok := profiles[profile]; !ok {
		return false, nil
	}
	delete(profiles, profile)
	if len(profiles) > 0 {
		return true, WriteDocument(path, doc)
	}
	_ = os.Remove(path) // best-effort, matching the Python reference
	return true, nil
}

// -- Expiry formatting -------------------------------------------------------------

// FormatExpiry renders an expiry as the cross-SDK wire format (UTC, RFC
// 3339, second precision — e.g. "2026-07-04T10:00:00Z").
func FormatExpiry(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// ParseExpiry tolerates RFC 3339 (Z or numeric offsets) and zone-less ISO
// timestamps (assumed UTC, matching the Python reference).
func ParseExpiry(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t, true // no zone → UTC
	}
	return time.Time{}, false
}

// -- Cross-process lock -------------------------------------------------------------

// FileLock is the sibling ".lock" file held by exclusive-create
// (os.O_CREATE|os.O_EXCL). Protocol: retry every 100ms up to 10s; a lock file
// older than StaleAfter (60s, safely above the token-endpoint HTTP timeout) is
// stale and may be broken.
//
// Break and release are OWNERSHIP-AWARE. On acquire the lock file is stamped
// with "<pid> <unixNano>\n" (unique per acquisition); Release unlinks only
// when that exact content is still on disk, and a stale-break unlinks only
// when the content has not changed since it was observed. Without this a lock
// broken as stale while its owner was mid-refresh could be deleted twice and
// admit a concurrent refresh — two processes rotating the single-use refresh
// token, which the server family-revokes.
type FileLock struct {
	LockPath      string
	Timeout       time.Duration
	RetryInterval time.Duration
	StaleAfter    time.Duration
	held          bool
	ownerToken    string // exact bytes this instance wrote at acquire; gates ownership-aware release
}

// NewLock builds the lock for a credentials file (target + ".lock").
func NewLock(target string) *FileLock {
	return &FileLock{
		LockPath:      target + ".lock",
		Timeout:       lockTimeout,
		RetryInterval: lockRetryInterval,
		StaleAfter:    lockStaleAfter,
	}
}

func (l *FileLock) tryAcquire() bool {
	f, err := os.OpenFile(l.LockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	// pid + high-resolution timestamp uniquely identifies THIS acquisition, so
	// Release / breakStale can verify we still own the on-disk lock before
	// unlinking it (never delete a lock another process now holds).
	token := fmt.Sprintf("%d %d\n", os.Getpid(), time.Now().UnixNano())
	_, _ = f.WriteString(token)
	_ = f.Close()
	l.ownerToken = token
	l.held = true
	return true
}

// breakStale deletes a stale lock, but only when the on-disk content is still
// the stale content it observed — if another process replaced the lock (its
// own release + re-acquire) after the stat, the content differs and the live
// lock is left alone. True when a retry is worthwhile right now.
func (l *FileLock) breakStale() bool {
	seen, err := os.ReadFile(l.LockPath)
	if err != nil {
		return true // lock vanished between attempts — retry immediately
	}
	fi, err := os.Stat(l.LockPath)
	if err != nil {
		return true
	}
	if time.Since(fi.ModTime()) <= l.StaleAfter {
		return false
	}
	return l.removeIfUnchanged(string(seen))
}

// removeIfUnchanged unlinks the lock only when its on-disk content still equals
// seen. A changed content means another process already replaced the lock
// (released + re-acquired), so unlinking would free a lock we do not own and
// admit a concurrent refresh. Returns true when a retry is worthwhile.
func (l *FileLock) removeIfUnchanged(seen string) bool {
	again, err := os.ReadFile(l.LockPath)
	if err != nil {
		return true // vanished between checks — a retry is worthwhile
	}
	if string(again) != seen {
		return false
	}
	_ = os.Remove(l.LockPath)
	return true
}

// Acquire blocks until the lock is held, the timeout elapses, or ctx is done.
func (l *FileLock) Acquire(ctx context.Context) error {
	// First-ever login: ~/.knoxcall/ may not exist yet, and O_CREATE on the
	// lock path fails on a missing parent — which tryAcquire treats as
	// contention, spinning until the timeout. Create it up front.
	if dir := filepath.Dir(l.LockPath); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	deadline := time.Now().Add(l.Timeout)
	staleBroken := false
	for {
		if l.tryAcquire() {
			return nil
		}
		if !staleBroken && l.breakStale() {
			staleBroken = true
			if l.tryAcquire() {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("knoxcall: timed out waiting for the credentials file lock (%s)", l.LockPath)
		}
		if err := sleepCtx(ctx, l.RetryInterval); err != nil {
			return err
		}
	}
}

// Release unlinks the lock file, but ONLY when the on-disk lock is still the
// one this instance wrote. If our lock was judged stale and broken by another
// process that then took the lock, its content differs from ours — deleting it
// would free a lock we no longer own and admit a concurrent refresh (two
// processes rotating the single-use refresh token → server family-revoke).
// Safe to call when not held.
func (l *FileLock) Release() {
	if !l.held {
		return
	}
	l.held = false
	content, err := os.ReadFile(l.LockPath)
	if err != nil {
		return // already gone / unreadable — nothing of ours to unlink
	}
	if string(content) != l.ownerToken {
		return // no longer our lock — leave it for its current owner
	}
	_ = os.Remove(l.LockPath)
}

// sleepCtx sleeps for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
