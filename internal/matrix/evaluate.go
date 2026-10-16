// Package matrix evaluates explicit, human-provided authorization observations offline.
// It never sends requests, creates sessions, or decides whether a target is authorized.
package matrix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const InputSchema = "authmatrix.matrix/v1"
const ResultSchema = "authmatrix.result/v1"
const LimitBytes = 1 << 20

// Input is a collection of independently witnessed access-control observations.
type Input struct {
	Schema        string        `json:"schema"`
	Authorization Authorization `json:"authorization"`
	Cases         []Case        `json:"cases"`
}
type Authorization struct {
	Approved bool   `json:"approved"`
	Origin   string `json:"origin"` // synthetic or explicitly-authorized
	Scope    string `json:"scope"`
}
type Case struct {
	ID                       string       `json:"id"`
	Kind                     string       `json:"kind"`     // unauthenticated, horizontal, vertical
	Expected                 string       `json:"expected"` // allow, deny
	ObservedStatus           schemaStatus `json:"observed_status"`
	PositiveControlConfirmed schemaBool   `json:"positive_control_confirmed,omitempty"`
}

// schemaStatus accepts every JSON numeric spelling of an integral HTTP status.
// JSON Schema treats 200, 200.0 and 2e2 as the same integer. Go's default
// decoder into int rejects the latter two. Avoid float64 rounding, so a
// fractional number cannot be silently promoted to an integral status.
type schemaStatus int

func (s *schemaStatus) UnmarshalJSON(raw []byte) error {
	// The JSON decoder validates token syntax. Only numeric tokens are valid.
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' {
		return errors.New("HTTP status must be a JSON number")
	}
	number := string(raw)
	exponent := 0
	if pos := strings.IndexAny(number, "eE"); pos >= 0 {
		expText := number[pos+1:]
		neg := false
		expText = strings.TrimPrefix(expText, "+")
		if strings.HasPrefix(expText, "-") {
			neg = true
			expText = expText[1:]
		}
		expText = strings.TrimLeft(expText, "0")
		// At most one MiB of input exists. Any larger magnitude cannot
		// produce an HTTP status between 100 and 599.
		if len(expText) > 7 {
			return errors.New("HTTP status exponent out of range")
		}
		if expText != "" {
			val, err := strconv.Atoi(expText)
			if err != nil || val > LimitBytes+3 {
				return errors.New("HTTP status exponent out of range")
			}
			exponent = val
			if neg {
				exponent = -val
			}
		}
		number = number[:pos]
	}
	fractionLen := 0
	if pos := strings.IndexByte(number, '.'); pos >= 0 {
		fractionLen = len(number) - pos - 1
		number = number[:pos] + number[pos+1:]
	}
	significant := strings.TrimLeft(number, "0")
	if significant == "" {
		return errors.New("HTTP status zero is invalid")
	}
	scale := exponent - fractionLen
	if len(significant)+scale != 3 {
		return errors.New("HTTP status outside 100..599")
	}
	var numeric string
	if scale < 0 {
		if len(significant) < 3 || strings.Trim(significant[3:], "0") != "" {
			return errors.New("HTTP status is not an integer")
		}
		numeric = significant[:3]
	} else {
		numeric = significant + strings.Repeat("0", scale)
	}
	val, err := strconv.Atoi(numeric)
	if err != nil || val < 100 || val > 599 {
		return errors.New("HTTP status outside 100..599")
	}
	*s = schemaStatus(val)
	return nil
}

// schemaBool refuses JSON null for an optional boolean evidence control.
// encoding/json/v1 silently maps null to false for a plain bool field, while
// the published input schema permits only true/false if this key is present.
type schemaBool bool

func (b *schemaBool) UnmarshalJSON(raw []byte) error {
	switch string(raw) {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return errors.New("invalid evidence control boolean")
	}
	return nil
}

type Evidence struct {
	CaseSHA256     string `json:"case_sha256"`
	Kind           string `json:"kind"`
	Expected       string `json:"expected"`
	ObservedStatus int    `json:"observed_status"`
	Verdict        string `json:"verdict"`
	Confidence     string `json:"confidence"`
}
type Summary struct {
	Match           int `json:"match"`
	PotentialBypass int `json:"potential_bypass"`
	Inconclusive    int `json:"inconclusive"`
}
type Result struct {
	Schema         string     `json:"schema"`
	InputSHA256    string     `json:"input_sha256"`
	ScopeSHA256    string     `json:"scope_sha256"`
	EvidenceStatus string     `json:"evidence_status"`
	Summary        Summary    `json:"summary"`
	Evidence       []Evidence `json:"evidence"`
}

// Decode rejects malformed UTF-8, ambiguous JSON object keys, unknown fields,
// unauthorized origins and oversized observations before interpreting any evidence.
func Decode(raw []byte) (Input, error) {
	var in Input
	if len(raw) > LimitBytes {
		return in, errors.New("input exceeds 1 MiB limit")
	}
	if !utf8.Valid(raw) {
		return in, errors.New("invalid UTF-8")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return in, fmt.Errorf("invalid JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, errors.New("invalid matrix JSON or unknown fields")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return in, errors.New("trailing JSON data")
	}
	if in.Schema != InputSchema {
		return in, errors.New("unsupported input schema")
	}
	if !in.Authorization.Approved {
		return in, errors.New("explicit authorization approval required")
	}
	if in.Authorization.Origin != "synthetic" && in.Authorization.Origin != "explicitly-authorized" {
		return in, errors.New("origin must be synthetic or explicitly-authorized")
	}
	if !safeID(in.Authorization.Scope) {
		return in, errors.New("invalid scope identifier")
	}
	if len(in.Cases) < 1 || len(in.Cases) > 1000 {
		return in, errors.New("cases must contain 1..1000 observations")
	}
	seen := map[string]bool{}
	for _, c := range in.Cases {
		if !safeID(c.ID) {
			return in, errors.New("invalid case identifier")
		}
		if seen[c.ID] {
			return in, errors.New("duplicate case identifier")
		}
		seen[c.ID] = true
		if c.Kind != "horizontal" && c.Kind != "vertical" && c.Kind != "unauthenticated" {
			return in, errors.New("invalid case kind")
		}
		if c.Expected != "allow" && c.Expected != "deny" {
			return in, errors.New("invalid expected decision")
		}
		if c.ObservedStatus < 100 || c.ObservedStatus > 599 {
			return in, errors.New("observed_status must be HTTP 100..599")
		}
	}
	return in, nil
}
func safeID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

// json.Decoder matches struct field names case-insensitively, even with
// DisallowUnknownFields. For authorization evidence we require the exact
// versioned JSON names specified in the public input schema. This also
// prevents differently cased keys from overwriting previously decoded fields.
var canonicalInputKeys = map[string]struct{}{
	"schema": {}, "authorization": {}, "approved": {}, "origin": {},
	"scope": {}, "cases": {}, "id": {}, "kind": {}, "expected": {},
	"observed_status": {}, "positive_control_confirmed": {},
}

// rejectDuplicateKeys tokenizes every object including nested inputs, rejects
// aliases/noncanonical keys, and keeps decoder semantics deterministic.
func rejectDuplicateKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var consume func(depth int) error
	consume = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting too deep")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				if e != nil {
					return e
				}
				k, ok := t.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, ok := canonicalInputKeys[k]; !ok {
					return errors.New("noncanonical or unknown JSON object key")
				}
				if seen[k] {
					return errors.New("duplicate JSON object key")
				}
				seen[k] = true
				if err := consume(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := consume(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('}'), json.Delim(']'):
			return errors.New("unexpected JSON terminator")
		default:
			return nil
		}
	}
	if err := consume(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("extra JSON tokens")
	}
	return nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func Evaluate(raw []byte) (Result, error) {
	in, err := Decode(raw)
	if err != nil {
		return Result{}, err
	}
	out := Result{Schema: ResultSchema, InputSHA256: digest(raw), ScopeSHA256: digest([]byte(in.Authorization.Scope)), EvidenceStatus: "observed", Evidence: make([]Evidence, 0, len(in.Cases))}
	for _, c := range in.Cases {
		e := Evidence{CaseSHA256: digest([]byte(c.ID)), Kind: c.Kind, Expected: c.Expected, ObservedStatus: int(c.ObservedStatus), Confidence: "observation-only"}
		switch {
		case c.Expected == "deny" && c.ObservedStatus >= 200 && c.ObservedStatus <= 299:
			e.Verdict = "potential-bypass"
			out.Summary.PotentialBypass++
		case c.Expected == "allow" && c.ObservedStatus >= 200 && c.ObservedStatus <= 299:
			e.Verdict = "match"
			out.Summary.Match++
		case c.Expected == "deny" && (c.ObservedStatus == 401 || c.ObservedStatus == 403 || c.ObservedStatus == 404 && bool(c.PositiveControlConfirmed)):
			e.Verdict = "match"
			out.Summary.Match++
		default:
			e.Verdict = "inconclusive"
			out.Summary.Inconclusive++
		}
		out.Evidence = append(out.Evidence, e)
	}
	sort.Slice(out.Evidence, func(i, j int) bool {
		return strings.Compare(out.Evidence[i].CaseSHA256, out.Evidence[j].CaseSHA256) < 0
	})
	return out, nil
}
