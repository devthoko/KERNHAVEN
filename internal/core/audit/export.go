package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Export writes the matching records as JSON Lines, oldest first, with
// their chain hashes, so a copy kept elsewhere can be checked later
// (AT-F10-03, TH-52). It returns the number of records written.
func (l *Log) Export(ctx context.Context, f Filter, w io.Writer) (int, error) {
	where, args := f.where()
	rows, err := l.db.QueryContext(ctx, `SELECT `+recordColumns+` FROM audit_events`+where+` ORDER BY seq ASC`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	n := 0
	for rows.Next() {
		rec, _, err := scan(rows)
		if err != nil {
			return n, err
		}
		if err := enc.Encode(rec); err != nil {
			return n, err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	return n, bw.Flush()
}

// ExportSummary describes a checked export.
type ExportSummary struct {
	Records int    `json:"records"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
	Head    string `json:"head"`       // hash of the last record
	Linked  bool   `json:"linked"`     // consecutive records, each linked to the one before
	Gaps    int    `json:"gaps"`       // places where records are missing (filtered exports)
	Genesis bool   `json:"from_start"` // the export starts with the first record ever
}

// CheckExport verifies every record of an export: each record's hash must
// match its content, and consecutive records must be linked. A filtered
// export has gaps; its records are still checked one by one.
func CheckExport(r io.Reader) (ExportSummary, error) {
	var s ExportSummary
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var prev Record
	s.Linked = true
	for line := 1; sc.Scan(); line++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return s, fmt.Errorf("line %d: %w", line, err)
		}
		if rec.Details == nil {
			rec.Details = map[string]string{}
		}
		details, _ := json.Marshal(rec.Details)
		want, err := computeHash(rec.PrevHash, toCanonical(rec, details))
		if err != nil {
			return s, err
		}
		if want != rec.Hash {
			return s, fmt.Errorf("line %d: record %d does not match its hash (modified)", line, rec.Seq)
		}
		if s.Records == 0 {
			s.First = rec.Seq
			s.Genesis = rec.Seq == 1 && rec.PrevHash == genesisHash
		} else {
			switch {
			case rec.Seq <= prev.Seq:
				return s, fmt.Errorf("line %d: record %d is out of order", line, rec.Seq)
			case rec.Seq == prev.Seq+1 && rec.PrevHash != prev.Hash:
				return s, fmt.Errorf("line %d: record %d is not linked to record %d (a record was replaced)", line, rec.Seq, prev.Seq)
			case rec.Seq != prev.Seq+1:
				s.Gaps++
				s.Linked = false
			}
		}
		s.Records++
		s.Last, s.Head = rec.Seq, rec.Hash
		prev = rec
	}
	if err := sc.Err(); err != nil {
		return s, err
	}
	if s.Records == 0 {
		return s, errors.New("the export contains no records")
	}
	return s, nil
}

// Continues reports whether a newer full export still contains the last
// record of an older one unchanged: a log truncated or rewritten between the
// two exports does not (TH-52).
func Continues(older ExportSummary, newer io.Reader) error {
	sc := bufio.NewScanner(newer)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var rec struct {
			Seq  int64  `json:"seq"`
			Hash string `json:"hash"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Seq != older.Last {
			continue
		}
		if rec.Hash != older.Head {
			return fmt.Errorf("record %d differs from the older export (the log was rewritten)", older.Last)
		}
		return nil
	}
	return fmt.Errorf("record %d of the older export is missing (the log was truncated or the export filtered)", older.Last)
}
