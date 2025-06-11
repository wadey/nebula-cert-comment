package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/slackhq/nebula/cert"
)

//go:generate go tool stringer -linecomment -type=FormatType
type FormatType int

const (
	FormatInvalid     FormatType = iota
	FormatName                   // name
	FormatVersion                // version
	FormatCurve                  // curve
	FormatGroups                 // groups
	FormatNotAfter               // notAfter
	FormatFingerprint            // fingerprint
)

func ParseFormatType(s string) FormatType {
	s = strings.ToLower(s)
	l := strings.ToLower(_FormatType_name)
	for i := range len(_FormatType_index) - 1 {
		if s == l[_FormatType_index[i]:_FormatType_index[i+1]] {
			return FormatType(i)
		}
	}
	return FormatType(0)
}

type FormatEntry struct {
	Type FormatType

	Exclude string
}

func ParseFormatEntries(entries string) ([]FormatEntry, error) {
	fes := []FormatEntry{}

	for e := range strings.SplitSeq(entries, ",") {
		fe, err := ParseFormatEntry(e)
		if err != nil {
			return nil, err
		}
		fes = append(fes, fe)
	}

	return fes, nil
}

func ParseFormatEntry(entry string) (fe FormatEntry, err error) {
	parts := strings.Split(entry, ":")
	ft := ParseFormatType(parts[0])
	if ft == 0 {
		return fe, fmt.Errorf("invalid format type: %q", entry)
	}
	fe.Type = ft

	if len(parts) > 1 {
		for _, p := range parts[1:] {
			switch {
			case strings.HasPrefix(p, "!="):
				fe.Exclude = strings.TrimPrefix(p, "!=")
			default:
				return fe, fmt.Errorf("invalid format modifier: %q", p)
			}
		}
	}
	return
}

func (f FormatEntry) Format(c cert.Certificate, outBuf *bytes.Buffer) error {
	s, err := f.String(c)
	if err != nil {
		return err
	}
	if s == "" || f.Exclude == s {
		return nil
	}

	if f.AddQuotes(s) {
		fmt.Fprintf(outBuf, " %s=%q", f.Type, s)
	} else {
		fmt.Fprintf(outBuf, " %s=%s", f.Type, s)
	}
	return nil
}

func (f FormatEntry) String(c cert.Certificate) (string, error) {
	switch f.Type {
	case FormatName:
		return c.Name(), nil
	case FormatVersion:
		return strconv.Itoa(int(c.Version())), nil
	case FormatCurve:
		return c.Curve().String(), nil
	case FormatGroups:
		return strings.Join(c.Groups(), ","), nil
	case FormatNotAfter:
		return c.NotAfter().UTC().Format("2006-01-02"), nil
	case FormatFingerprint:
		return c.Fingerprint()

	default:
		return "", fmt.Errorf("invalid type: %s", f.Type)
	}
}

func (f FormatEntry) AddQuotes(s string) bool {
	// TODO make configurable?
	return strings.Contains(s, " ")
}
