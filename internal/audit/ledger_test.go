package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func testKey() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func newTestLedger(t *testing.T, path string) *Ledger {
	t.Helper()
	l, err := NewLedger(path, testKey())
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	return l
}

func TestAppendVerifyAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l := newTestLedger(t, path)

	for _, decision := range []string{"ALLOW", "DENY", "ALLOW_HITL"} {
		if _, err := l.Append("sess", "query_db", `{"query":"SELECT 1"}`, decision, "tester"); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	count, err := l.VerifyChain()
	if err != nil || count != 3 {
		t.Fatalf("VerifyChain = %d, %v", count, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l = newTestLedger(t, path)
	defer l.Close()
	if _, err := l.Append("sess", "execute_code", `{}`, "ALLOW", "tester"); err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}
	count, err = l.VerifyChain()
	if err != nil || count != 4 {
		t.Fatalf("VerifyChain after reopen = %d, %v", count, err)
	}
}

func TestDetectsTamperedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l := newTestLedger(t, path)
	defer l.Close()
	if _, err := l.Append("sess", "query_db", `{}`, "ALLOW", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append("sess", "query_db", `{}`, "DENY", "tester"); err != nil {
		t.Fatal(err)
	}

	if _, err := l.db.Exec(`UPDATE audit_log SET decision = 'ALLOW' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.VerifyChain(); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestDetectsTailTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l := newTestLedger(t, path)
	defer l.Close()
	for i := 0; i < 2; i++ {
		if _, err := l.Append("sess", "query_db", `{}`, "ALLOW", "tester"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.VerifyChain(); err == nil {
		t.Fatal("expected truncation detection")
	}
}

func TestWrongKeyAndMissingKeyAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l := newTestLedger(t, path)
	if _, err := l.Append("sess", "query_db", `{}`, "ALLOW", "tester"); err != nil {
		t.Fatal(err)
	}
	l.Close()

	if _, err := NewLedger(path, []byte("abcdef0123456789abcdef0123456789")); err == nil {
		t.Fatal("expected wrong key rejection")
	}
	if _, err := NewLedger(path, nil); err == nil {
		t.Fatal("expected missing key rejection for MAC-protected ledger")
	}
}

func TestLegacyLedgerWithoutKeyStillVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	l, err := NewLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append("sess", "query_db", `{}`, "ALLOW", "tester"); err != nil {
		t.Fatal(err)
	}
	if count, err := l.VerifyChain(); err != nil || count != 1 {
		t.Fatalf("VerifyChain = %d, %v", count, err)
	}
	l.Close()

	l, err = NewLedger(path, nil)
	if err != nil {
		t.Fatalf("reopen legacy: %v", err)
	}
	defer l.Close()
	if count, err := l.VerifyChain(); err != nil || count != 1 {
		t.Fatalf("VerifyChain after reopen = %d, %v", count, err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.key")
	key, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if len(key) < 16 {
		t.Fatalf("key too short: %d", len(key))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if string(loaded) != string(key) {
		t.Fatal("loaded key does not match created key")
	}
}

func TestReadOnlyVerification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l := newTestLedger(t, path)
	if _, err := l.Append("sess", "query_db", `{}`, "ALLOW", "tester"); err != nil {
		t.Fatal(err)
	}
	l.Close()

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	ro, err := NewReadOnlyLedger(path, testKey())
	if err != nil {
		t.Fatalf("NewReadOnlyLedger: %v", err)
	}
	count, err := ro.VerifyChain()
	if err != nil || count != 1 {
		t.Fatalf("VerifyChain = %d, %v", count, err)
	}
	ro.Close()

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("read-only verification changed the database size: %d -> %d", before.Size(), after.Size())
	}

	if _, err := NewReadOnlyLedger(filepath.Join(t.TempDir(), "missing.db"), testKey()); err == nil {
		t.Fatal("expected read-only open of missing database to fail")
	}
}

func TestVerifyChainDoesNotDeadlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l := newTestLedger(t, path)
	defer l.Close()
	for i := 0; i < 5; i++ {
		if _, err := l.Append("sess", "tool", `{}`, "ALLOW", "tester"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.VerifyChain(); err != nil {
		t.Fatal(err)
	}
}
