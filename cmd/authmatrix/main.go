package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Shell-I-Byte/authmatrix/internal/matrix"
)

const version = "v0.1.0-rc10"

func usageTo(w io.Writer) {
	fmt.Fprintln(w, "usage: authmatrix evaluate -in FILE [-out FILE] | authmatrix version")
}
func usage() { usageTo(os.Stderr) }
func run(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help") {
		usageTo(os.Stdout)
		return 0
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(version)
		return 0
	}
	if len(args) < 1 || args[0] != "evaluate" {
		usage()
		return 2
	}
	f := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	in := f.String("in", "", "input JSON file")
	out := f.String("out", "", "write JSON file")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageTo(os.Stdout)
			return 0
		}
		usage()
		return 2
	}
	if len(f.Args()) > 0 || *in == "" {
		usage()
		return 2
	}
	raw, err := load(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: input unavailable, oversized, or not a regular file")
		return 2
	}
	result, err := matrix.Evaluate(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: invalid or unauthorized matrix input")
		return 2
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: cannot encode result")
		return 2
	}
	b = append(b, '\n')
	if *out == "" {
		if _, err = os.Stdout.Write(b); err != nil {
			return 2
		}
	} else {
		if err = save(*out, b); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: cannot safely write output")
			return 2
		}
	}
	if result.Summary.PotentialBypass > 0 {
		return 1
	}
	return 0
}
func load(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > matrix.LimitBytes {
		return nil, errors.New("invalid input file")
	}
	f, err := openInputFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
		return nil, errors.New("input file changed between inspection and open")
	}
	b, err := io.ReadAll(io.LimitReader(f, matrix.LimitBytes+1))
	if err != nil || len(b) > matrix.LimitBytes {
		return nil, errors.New("input size exceeded")
	}
	return b, nil
}
func main() { os.Exit(run(os.Args[1:])) }
