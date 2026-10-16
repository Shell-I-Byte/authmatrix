package matrix

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func valid() []byte {
	return []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"a","kind":"horizontal","expected":"allow","observed_status":200},{"id":"b","kind":"horizontal","expected":"deny","observed_status":200},{"id":"c","kind":"vertical","expected":"deny","observed_status":403},{"id":"d","kind":"unauthenticated","expected":"deny","observed_status":404}]}`)
}
func TestExpectedAndInconclusive(t *testing.T) {
	r, e := Evaluate(valid())
	if e != nil {
		t.Fatal(e)
	}
	if r.Summary.Match != 2 || r.Summary.PotentialBypass != 1 || r.Summary.Inconclusive != 1 {
		t.Fatalf("unexpected %+v", r.Summary)
	}
	if len(r.Evidence) != 4 || r.InputSHA256 == "" || r.ScopeSHA256 == "" {
		t.Fatalf("incomplete result %+v", r)
	}
	for _, v := range r.Evidence {
		if v.CaseSHA256 == "a" || v.CaseSHA256 == "b" {
			t.Fatal("raw id leaked")
		}
	}
}
func TestInvalidInputs(t *testing.T) {
	tests := map[string][]byte{
		"null": []byte(`null`), "missing approval": []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"origin":"synthetic","scope":"local"},"cases":[]}`), "unknown input field": append([]byte(`{"extra":1,`), valid()[1:]...),
		"duplicate key": []byte(`{"schema":"x","schema":"authmatrix.matrix/v1"}`), "duplicate nested": []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"approved":false}}`),
		"utf8": {0xff, 0xfe}, "trailing": append(valid(), []byte(` {}`)...), "oversize": []byte(strings.Repeat("x", LimitBytes+1)),
		"empty cases":     []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[]}`),
		"unicode control": []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"\u001bX","kind":"horizontal","expected":"allow","observed_status":200}]}`),
		"duplicate id":    []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"a","kind":"horizontal","expected":"allow","observed_status":200},{"id":"a","kind":"horizontal","expected":"deny","observed_status":403}]}`),
		"bad status":      []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"a","kind":"horizontal","expected":"allow","observed_status":999}]}`),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, e := Evaluate(b); e == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}
func TestStatusBoundaries(t *testing.T) {
	for _, x := range []struct {
		status    int
		expect    string
		confirmed bool
	}{{200, "potential-bypass", false}, {299, "potential-bypass", false}, {300, "inconclusive", false}, {401, "match", false}, {403, "match", false}, {404, "inconclusive", false}, {404, "match", true}, {429, "inconclusive", false}, {500, "inconclusive", false}, {599, "inconclusive", false}} {
		raw := []byte(fmt.Sprintf(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"x","kind":"horizontal","expected":"deny","observed_status":%d,"positive_control_confirmed":%t}]}`, x.status, x.confirmed))
		r, e := Evaluate(raw)
		if e != nil || r.Evidence[0].Verdict != x.expect {
			t.Fatalf("status %d ctrl %t => %+v err %v", x.status, x.confirmed, r, e)
		}
	}
}
func TestDeterminismConcurrent(t *testing.T) {
	b := valid()
	base, e := Evaluate(b)
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := json.Marshal(base)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := Evaluate(b)
			if e != nil {
				errs <- e
				return
			}
			got, _ := json.Marshal(r)
			if string(got) != string(expected) {
				errs <- fmt.Errorf("non deterministic")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
func FuzzEvaluate(f *testing.F) {
	f.Add(valid())
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > LimitBytes {
			return
		}
		_, _ = Evaluate(b)
	})
}

func TestMaxCasesAndBoundary(t *testing.T) {
	in := Input{Schema: InputSchema, Authorization: Authorization{Approved: true, Origin: "synthetic", Scope: "fixture"}}
	for i := 0; i < 1000; i++ {
		in.Cases = append(in.Cases, Case{ID: fmt.Sprintf("case-%04d", i), Kind: "horizontal", Expected: "deny", ObservedStatus: 403})
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Evaluate(b)
	if err != nil || len(r.Evidence) != 1000 || r.Summary.Match != 1000 {
		t.Fatalf("1000-case boundary: %+v %v", r.Summary, err)
	}
	in.Cases = append(in.Cases, Case{ID: "overflow", Kind: "horizontal", Expected: "allow", ObservedStatus: 200})
	b, _ = json.Marshal(in)
	if _, err := Evaluate(b); err == nil {
		t.Fatal("accepted 1001 cases")
	}
}

func TestNoSensitiveLabelsInReport(t *testing.T) {
	raw := []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"explicitly-authorized","scope":"corpSecret"},"cases":[{"id":"secretUser01","kind":"horizontal","expected":"allow","observed_status":204}]}`)
	r, err := Evaluate(raw)
	if err != nil {
		t.Fatal(err)
	}
	rendered, _ := json.Marshal(r)
	for _, label := range []string{"corpSecret", "secretUser01"} {
		if strings.Contains(string(rendered), label) {
			t.Fatalf("label %q leaked", label)
		}
	}
}

// TestCanonicalSchemaKeys verifies that JSON aliases accepted by Go's legacy
// case-insensitive struct decoder cannot promote a denied authorization or
// override evidence status contrary to the published strict JSON Schema.
func TestCanonicalSchemaKeys(t *testing.T) {
	inputs := map[string][]byte{
		"mixed authorization approval": []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":false,"Approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"x","kind":"horizontal","expected":"deny","observed_status":403}]}`),
		"mixed origin":                 []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"unknown","Origin":"synthetic","scope":"local"},"cases":[{"id":"x","kind":"horizontal","expected":"deny","observed_status":403}]}`),
		"uppercase root":               []byte(`{"schema":"authmatrix.matrix/v1","Authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"x","kind":"horizontal","expected":"deny","observed_status":403}]}`),
		"uppercase cases":              []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"Cases":[{"id":"x","kind":"horizontal","expected":"deny","observed_status":403}]}`),
		"uppercase case field":         []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"x","kind":"horizontal","expected":"deny","observed_status":403,"Observed_Status":200}]}`),
		"unicode simple fold":          []byte(`{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local"},"cases":[{"id":"x","kind":"horizontal","expected":"deny","obſerved_status":403}]}`),
	}
	for name, raw := range inputs {
		t.Run(name, func(t *testing.T) {
			if _, err := Evaluate(raw); err == nil {
				t.Fatalf("accepted noncanonical JSON field(s): %s", raw)
			}
		})
	}
	if _, err := Evaluate(valid()); err != nil {
		t.Fatalf("rejected normal canonical input: %v", err)
	}
}

// BUG-AM-093-001: optional fields must still respect their JSON Schema type.
// In RC3 encoding/json/v1 silently accepted null as false, losing the crucial
// distinction between absent evidence and explicitly malformed control data.
func TestOptionalPositiveControlBooleanStrict(t *testing.T) {
	base := `{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"fixture"},"cases":[{"id":"test","kind":"horizontal","expected":"deny","observed_status":404%s}]}`
	for _, tc := range []struct {
		name, value string
		reject      bool
		verdict     string
	}{
		{"null", `,"positive_control_confirmed":null`, true, ""},
		{"string", `,"positive_control_confirmed":"true"`, true, ""},
		{"number", `,"positive_control_confirmed":1`, true, ""},
		{"object", `,"positive_control_confirmed":{}`, true, ""},
		{"true", `,"positive_control_confirmed":true`, false, "match"},
		{"false", `,"positive_control_confirmed":false`, false, "inconclusive"},
		{"absent", "", false, "inconclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Evaluate([]byte(fmt.Sprintf(base, tc.value)))
			if tc.reject {
				if err == nil {
					t.Fatalf("schema-invalid %s was accepted: %+v", tc.name, report)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid %s rejected: %v", tc.name, err)
			}
			if len(report.Evidence) != 1 || report.Evidence[0].Verdict != tc.verdict {
				t.Fatalf("wrong %s verdict: %+v", tc.name, report)
			}
		})
	}
}

// BUG-AM-119-001: JSON Schema integer accepts numerical-equivalent decimal
// and exponent spellings, but ordinary Go int decoding refused them in RC4.
func TestJSONSchemaIntegerNumericRepresentations(t *testing.T) {
	fixture := `{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"fixture"},"cases":[{"id":"one","kind":"horizontal","expected":"deny","observed_status":%s}]}`
	for _, tc := range []struct {
		number   string
		accepted bool
		status   int
	}{
		{"200", true, 200}, {"200.0", true, 200}, {"2e2", true, 200},
		{"2E+02", true, 200}, {"200.000", true, 200}, {"0.0002e6", true, 200},
		{"599.0", true, 599}, {"1e2", true, 100}, {"5.99e2", true, 599},
		{"100.00000000000000000000000000000001", false, 0},
		{"200.00000000000000000000000000000001", false, 0},
		{"200.01", false, 0}, {"599.1", false, 0}, {"600.0", false, 0},
		{"99.0", false, 0}, {"0.0", false, 0}, {"-200.0", false, 0},
		{"2e999999999999999", false, 0}, {"2e-999999999999999", false, 0},
		{"null", false, 0}, {`"200"`, false, 0}, {"true", false, 0},
	} {
		t.Run(tc.number, func(t *testing.T) {
			out, err := Evaluate([]byte(fmt.Sprintf(fixture, tc.number)))
			if (err == nil) != tc.accepted {
				t.Fatalf("token %s accepted=%v error=%v", tc.number, err == nil, err)
			}
			if tc.accepted && (len(out.Evidence) != 1 || out.Evidence[0].ObservedStatus != tc.status) {
				t.Fatalf("incorrect normalized numeric status: %#v", out)
			}
		})
	}
}
