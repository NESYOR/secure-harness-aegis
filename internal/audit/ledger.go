package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	genesisHash = "GENESIS_00000000000000000000000000000000000000000000000000000000"
	stateID     = 1
)

// Ledger is an append-only, hash-chained audit log. When a key is configured
// each row and the ledger head are also authenticated with HMAC-SHA256, which
// prevents an attacker with database write access from silently recomputing
// the chain.
type Ledger struct {
	db       *sql.DB
	key      []byte
	mu       sync.Mutex
	lastHash string
	count    int64
}

type AuditEntry struct {
	ID        int64
	Timestamp string
	SessionID string
	Tool      string
	ArgsJSON  string
	Decision  string
	Approver  string
	PrevHash  string
	Hash      string
	MAC       string
}

// LoadOrCreateKey returns the audit HMAC key from AEGIS_AUDIT_HMAC_KEY or from
// keyPath, creating a new 256-bit key with 0600 permissions if necessary.
func LoadOrCreateKey(keyPath string) ([]byte, error) {
	if env := os.Getenv("AEGIS_AUDIT_HMAC_KEY"); env != "" {
		key := []byte(env)
		if len(key) < 16 {
			return nil, errors.New("AEGIS_AUDIT_HMAC_KEY must be at least 16 bytes")
		}
		return key, nil
	}
	if keyPath == "" {
		return nil, errors.New("audit key path is required")
	}

	raw, err := os.ReadFile(keyPath)
	if err == nil {
		// Tighten permissions on a pre-existing key file.
		_ = os.Chmod(keyPath, 0o600)
		return decodeKeyFile(raw, keyPath)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading audit key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating audit key: %w", err)
	}
	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("creating audit key directory: %w", err)
		}
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("writing audit key: %w", err)
	}
	return key, nil
}

// LoadKey reads the audit key from the environment or keyPath.
func LoadKey(keyPath string) ([]byte, error) {
	if env := os.Getenv("AEGIS_AUDIT_HMAC_KEY"); env != "" {
		if len(env) < 16 {
			return nil, errors.New("AEGIS_AUDIT_HMAC_KEY must be at least 16 bytes")
		}
		return []byte(env), nil
	}
	if keyPath == "" {
		return nil, errors.New("audit key path is required")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading audit key: %w", err)
	}
	return decodeKeyFile(raw, keyPath)
}

func decodeKeyFile(raw []byte, path string) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) >= 16 {
		return decoded, nil
	}
	if len(trimmed) >= 16 {
		return []byte(trimmed), nil
	}
	return nil, fmt.Errorf("audit key file %s is invalid", path)
}

// NewLedger opens or creates the ledger. key may be nil for legacy ledgers
// without MACs; a key is strongly recommended and is required to verify a
// ledger created with one.
func NewLedger(dbPath string, key []byte) (*Ledger, error) {
	return openLedger(dbPath, key, false)
}

// NewReadOnlyLedger opens an existing ledger without creating, migrating, or
// writing anything. It is intended for forensic verification.
func NewReadOnlyLedger(dbPath string, key []byte) (*Ledger, error) {
	return openLedger(dbPath, key, true)
}

func openLedger(dbPath string, key []byte, readOnly bool) (*Ledger, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("audit database path is required")
	}

	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	if readOnly {
		dsn = "file:" + dbPath + "?mode=ro&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection serializes writers and avoids losable WAL locks.
	db.SetMaxOpenConns(1)

	if readOnly {
		for _, table := range []string{"audit_log", "ledger_state"} {
			ok, err := tableExists(db, table)
			if err != nil {
				db.Close()
				return nil, err
			}
			if !ok {
				db.Close()
				return nil, fmt.Errorf("audit ledger is missing table %q; start the gateway once to migrate it", table)
			}
		}
		hasMAC, err := columnExists(db, "audit_log", "mac")
		if err != nil {
			db.Close()
			return nil, err
		}
		if !hasMAC {
			db.Close()
			return nil, errors.New("audit ledger predates MAC authentication; start the gateway once to migrate it")
		}
	} else {
		schema := `
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			session_id TEXT NOT NULL,
			tool TEXT NOT NULL,
			args_json TEXT NOT NULL,
			decision TEXT NOT NULL,
			approver TEXT NOT NULL,
			prev_hash TEXT NOT NULL,
			hash TEXT NOT NULL,
			mac TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS ledger_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_hash TEXT NOT NULL,
			count INTEGER NOT NULL,
			mac TEXT NOT NULL DEFAULT ''
		);`
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, err
		}

		hasMAC, err := columnExists(db, "audit_log", "mac")
		if err != nil {
			db.Close()
			return nil, err
		}
		if !hasMAC {
			if _, err := db.Exec(`ALTER TABLE audit_log ADD COLUMN mac TEXT NOT NULL DEFAULT ''`); err != nil {
				db.Close()
				return nil, fmt.Errorf("migrating audit_log: %w", err)
			}
		}
	}

	l := &Ledger{db: db, key: key, lastHash: genesisHash}

	if err := l.loadState(readOnly); err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

func tableExists(db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return name == table, nil
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (l *Ledger) loadState(readOnly bool) error {
	var rowCount int64
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&rowCount); err != nil {
		return fmt.Errorf("counting audit records: %w", err)
	}

	var tailHash string
	if rowCount > 0 {
		if err := l.db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&tailHash); err != nil {
			return fmt.Errorf("reading audit tail: %w", err)
		}
	} else {
		tailHash = genesisHash
	}

	var stateHash, stateMAC string
	var stateCount int64
	err := l.db.QueryRow(`SELECT last_hash, count, mac FROM ledger_state WHERE id = ?`, stateID).
		Scan(&stateHash, &stateCount, &stateMAC)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if readOnly {
			return errors.New("audit ledger has no authenticated head; start the gateway once to migrate it")
		}
		// Migrate a legacy ledger on first open.
		if rowCount > 0 {
			if err := l.writeState(tailHash, rowCount); err != nil {
				return fmt.Errorf("initializing audit state: %w", err)
			}
		} else {
			if err := l.writeState(genesisHash, 0); err != nil {
				return fmt.Errorf("initializing audit state: %w", err)
			}
		}
	case err != nil:
		return fmt.Errorf("reading audit state: %w", err)
	default:
		if len(l.key) == 0 && stateMAC != "" {
			return errors.New("audit ledger is MAC-protected; provide AEGIS_AUDIT_HMAC_KEY or --audit-key-file")
		}
		if len(l.key) > 0 && !l.validMAC(stateMAC, statePayload(stateHash, stateCount)) {
			return errors.New("audit state MAC mismatch: ledger key is wrong or the state was tampered with")
		}
		if stateCount != rowCount || stateHash != tailHash {
			return fmt.Errorf("audit ledger state mismatch (state count=%d, rows=%d): possible truncation or deletion", stateCount, rowCount)
		}
	}

	l.lastHash = tailHash
	l.count = rowCount
	return nil
}

func (l *Ledger) writeState(lastHash string, count int64) error {
	_, err := l.db.Exec(
		`INSERT INTO ledger_state (id, last_hash, count, mac) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET last_hash=excluded.last_hash, count=excluded.count, mac=excluded.mac`,
		stateID, lastHash, count, l.mac(statePayload(lastHash, count)),
	)
	return err
}

func statePayload(hash string, count int64) string {
	return fmt.Sprintf("state|%s|%d", hash, count)
}

func rowPayload(hash string) string {
	return "row|" + hash
}

func (l *Ledger) mac(payload string) string {
	if len(l.key) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func (l *Ledger) validMAC(actual, payload string) bool {
	expected := l.mac(payload)
	if expected == "" || actual == "" {
		return false
	}
	return hmac.Equal([]byte(actual), []byte(expected))
}

func computeHash(ts, session, tool, args, decision, approver, prevHash string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", ts, session, tool, args, decision, approver, prevHash)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Append adds one record and advances the authenticated ledger head in the
// same transaction. Callers should fail closed if this returns an error.
func (l *Ledger) Append(sessionID, tool, argsJSON, decision, approver string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	h := computeHash(ts, sessionID, tool, argsJSON, decision, approver, l.lastHash)
	mac := l.mac(rowPayload(h))
	nextCount := l.count + 1

	tx, err := l.db.Begin()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO audit_log (timestamp, session_id, tool, args_json, decision, approver, prev_hash, hash, mac)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, sessionID, tool, argsJSON, decision, approver, l.lastHash, h, mac,
	); err != nil {
		_ = tx.Rollback()
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO ledger_state (id, last_hash, count, mac) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET last_hash=excluded.last_hash, count=excluded.count, mac=excluded.mac`,
		stateID, h, nextCount, l.mac(statePayload(h, nextCount)),
	); err != nil {
		_ = tx.Rollback()
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}

	l.lastHash = h
	l.count = nextCount
	return h, nil
}

// VerifyChain recomputes the full hash chain, validates every MAC, and checks
// the authenticated head so that tail truncation is detected.
func (l *Ledger) VerifyChain() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rows, err := l.db.Query(`SELECT id, timestamp, session_id, tool, args_json, decision, approver, prev_hash, hash, mac FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	// Keep a defensive close for early returns; the explicit close below is
	// still required before the head query because the ledger uses a single
	// SQLite connection.
	defer rows.Close()
	expectedPrev := genesisHash
	count := 0
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SessionID, &e.Tool, &e.ArgsJSON, &e.Decision, &e.Approver, &e.PrevHash, &e.Hash, &e.MAC); err != nil {
			return count, err
		}
		if e.PrevHash != expectedPrev {
			return count, fmt.Errorf("chain broken at row %d: expected prev_hash %s, got %s", e.ID, expectedPrev, e.PrevHash)
		}
		recalc := computeHash(e.Timestamp, e.SessionID, e.Tool, e.ArgsJSON, e.Decision, e.Approver, e.PrevHash)
		if recalc != e.Hash {
			return count, fmt.Errorf("tampered record at row %d: hash mismatch", e.ID)
		}
		if len(l.key) > 0 && e.MAC == "" {
			return count, fmt.Errorf("row %d has no MAC: ledger predates authentication or was tampered with", e.ID)
		}
		if len(l.key) > 0 && !l.validMAC(e.MAC, rowPayload(e.Hash)) {
			return count, fmt.Errorf("tampered record at row %d: MAC mismatch", e.ID)
		}
		if len(l.key) == 0 && e.MAC != "" {
			return count, errors.New("ledger is MAC-protected; provide AEGIS_AUDIT_HMAC_KEY or --audit-key-file")
		}
		expectedPrev = e.Hash
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	// Close before reading the head: the ledger uses a single SQLite
	// connection to serialize writers, so an open row cursor would deadlock.
	if err := rows.Close(); err != nil {
		return count, err
	}

	var stateHash, stateMAC string
	var stateCount int64
	err = l.db.QueryRow(`SELECT last_hash, count, mac FROM ledger_state WHERE id = ?`, stateID).
		Scan(&stateHash, &stateCount, &stateMAC)
	if errors.Is(err, sql.ErrNoRows) {
		return count, errors.New("missing authenticated ledger head: possible truncation")
	}
	if err != nil {
		return count, err
	}
	if stateCount != int64(count) {
		return count, fmt.Errorf("ledger head count mismatch: state=%d, rows=%d (possible truncation)", stateCount, count)
	}
	if stateHash != expectedPrev {
		return count, fmt.Errorf("ledger head hash mismatch: possible truncation")
	}
	if len(l.key) > 0 && !l.validMAC(stateMAC, statePayload(stateHash, stateCount)) {
		return count, errors.New("ledger head MAC mismatch")
	}
	if len(l.key) == 0 && stateMAC != "" {
		return count, errors.New("ledger is MAC-protected; provide AEGIS_AUDIT_HMAC_KEY or --audit-key-file")
	}
	return count, nil
}

func (l *Ledger) Close() error {
	return l.db.Close()
}
