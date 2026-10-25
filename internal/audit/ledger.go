package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Ledger struct {
	db       *sql.DB
	mu       sync.Mutex
	lastHash string
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
}

func NewLedger(dbPath string) (*Ledger, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}

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
		hash TEXT NOT NULL
	);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	l := &Ledger{db: db, lastHash: "GENESIS_00000000000000000000000000000000000000000000000000000000"}
	var last string
	err = db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&last)
	if err == nil && last != "" {
		l.lastHash = last
	}
	return l, nil
}

func computeHash(ts, session, tool, args, decision, approver, prevHash string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", ts, session, tool, args, decision, approver, prevHash)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (l *Ledger) Append(sessionID, tool, argsJSON, decision, approver string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	h := computeHash(ts, sessionID, tool, argsJSON, decision, approver, l.lastHash)

	_, err := l.db.Exec(
		`INSERT INTO audit_log (timestamp, session_id, tool, args_json, decision, approver, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, sessionID, tool, argsJSON, decision, approver, l.lastHash, h,
	)
	if err != nil {
		return "", err
	}
	l.lastHash = h
	return h, nil
}

func (l *Ledger) VerifyChain() (int, error) {
	rows, err := l.db.Query(`SELECT id, timestamp, session_id, tool, args_json, decision, approver, prev_hash, hash FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	expectedPrev := "GENESIS_00000000000000000000000000000000000000000000000000000000"
	count := 0
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SessionID, &e.Tool, &e.ArgsJSON, &e.Decision, &e.Approver, &e.PrevHash, &e.Hash); err != nil {
			return count, err
		}
		if e.PrevHash != expectedPrev {
			return count, fmt.Errorf("chain broken at row %d: expected prev_hash %s, got %s", e.ID, expectedPrev, e.PrevHash)
		}
		recalc := computeHash(e.Timestamp, e.SessionID, e.Tool, e.ArgsJSON, e.Decision, e.Approver, e.PrevHash)
		if recalc != e.Hash {
			return count, fmt.Errorf("tampered record at row %d: hash mismatch", e.ID)
		}
		expectedPrev = e.Hash
		count++
	}
	return count, nil
}

func (l *Ledger) Close() error {
	return l.db.Close()
}
