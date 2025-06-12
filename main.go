package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/slackhq/nebula/cert"
	"github.com/wadey/nebula-cert-comment/internal/diff"
)

type processor struct {
	debug bool

	commentPrefix string
	formatters    []FormatEntry

	// buffer for original source file bytes
	srcBuf bytes.Buffer

	// buffer for output file bytes
	outBuf bytes.Buffer

	// buffer for trimmed certificate block bytes
	crtBuf bytes.Buffer

	// buffer for raw certificate block bytes
	crtRaw bytes.Buffer
}

func comment(formatters []FormatEntry, outBuf, crtBuf *bytes.Buffer) error {
	c, _, err := cert.UnmarshalCertificateFromPEM(crtBuf.Bytes())
	if err != nil {
		return err
	}

	for _, e := range formatters {
		err := e.Format(c, outBuf)
		if err != nil {
			return err
		}
	}
	outBuf.WriteRune('\n')

	return nil
}

func (p *processor) processFile(path string) (bool, error) {
	p.srcBuf.Reset()
	p.outBuf.Reset()
	p.crtBuf.Reset()
	p.crtRaw.Reset()

	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	line := 1
	inCert := false
	certPad := ""
	foundCert := false

	eof := false
	for !eof {
		bs, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				eof = true
			} else {
				return foundCert, err
			}
		}

		// Check first line for binary file indicators
		if line == 1 {
			isBinary := bytes.IndexByte(bs, 0) != -1
			if isBinary {
				if p.debug {
					fmt.Fprintf(os.Stderr, "skipping binary file: %q\n", path)
				}
				break
			}
		}

		_, err = p.srcBuf.Write(bs)
		if err != nil {
			return foundCert, err
		}

		text := string(bs)
		trimText := strings.TrimLeft(text, " \t")

		switch {
		case strings.HasPrefix(trimText, "-----BEGIN NEBULA CERTIFICATE-----"),
			strings.HasPrefix(trimText, "-----BEGIN NEBULA CERTIFICATE V2-----"):
			if text[0] != '-' {
				s := strings.SplitN(text, "-", 2)
				certPad = s[0]
			}
			inCert = true
			p.crtBuf.WriteString(strings.TrimPrefix(text, certPad))
			p.crtRaw.WriteString(text)
		case strings.HasPrefix(trimText, "-----END NEBULA CERTIFICATE-----"),
			strings.HasPrefix(trimText, "-----END NEBULA CERTIFICATE V2-----"):
			p.crtBuf.WriteString(strings.TrimPrefix(text, certPad))
			p.crtRaw.WriteString(text)

			// Write the comment line
			p.outBuf.WriteString(certPad)
			fmt.Fprint(&p.outBuf, p.commentPrefix)
			err = comment(p.formatters, &p.outBuf, &p.crtBuf)
			if err != nil {
				return true, err
			}

			// Write the raw cert block
			_, err = p.crtRaw.WriteTo(&p.outBuf)
			if err != nil {
				return true, err
			}
			p.crtBuf.Reset()
			p.crtRaw.Reset()

			certPad = ""
			inCert = false
			foundCert = true
		case strings.HasPrefix(trimText, p.commentPrefix):
			// Skip and regenerate
		default:
			if inCert {
				p.crtBuf.WriteString(strings.TrimPrefix(text, certPad))
				p.crtRaw.WriteString(text)
			} else {
				p.outBuf.WriteString(text)
			}
		}

		line += 1
	}

	return foundCert, nil
}

func write(path string, fileBuf *bytes.Buffer) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = fileBuf.WriteTo(file)
	if err != nil {
		return err
	}

	return nil
}

type Flags struct {
	Diff    bool
	Write   bool
	List    bool
	Exit    bool
	Debug   bool
	Version bool

	LargeFileLimit int64
	CommentPrefix  string
	Format         string
}

func parseFlags() (*Flags, []string) {
	flags := &Flags{}

	flag.BoolVar(&flags.Diff, "d", false, "display diffs")
	flag.BoolVar(&flags.Write, "w", false, "write result to files")
	flag.BoolVar(&flags.List, "l", false, "list files whose comments need updating")
	flag.BoolVar(&flags.Exit, "e", false, "exit(1) if changes needed/made")
	flag.BoolVar(&flags.Debug, "debug", false, "log files we are skipping")
	flag.BoolVar(&flags.Version, "version", false, "print version and exit")

	flag.Int64Var(&flags.LargeFileLimit, "large-file-limit", 10*1000*1000, "don't process files larger than this in bytes, Set to 0 to disable")
	flag.StringVar(&flags.CommentPrefix, "comment", "# nebula:", "prefix for comment lines")
	flag.StringVar(&flags.Format, "format", "name,version:!=1,groups:?,networks:?,unsafeNetworks:?,notAfter,fingerprint", "The formatters to use for the comment")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nebula-cert-comment [OPTION]... [FILE]...\n\n")
		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, `

If none of "-d, -l, -w" are specified, defaults to "-d".

If a directory is specified for FILE, it is searched recursively. Symlinks are currently skipped.

Format string is a comma separated list of formatters with optional modifiers (separated by colons)

    Formatters:

        name            --  name of the certificate
        version         --  version of the certificate
        curve           --  curve of the certificate
        groups          --  comma separated list of groups defined on the certificate (omitted if empty)
        notAfter        --  expiration timestamp in UTC of the certificate, formatted as YYYY-MM-DD
        fingerprint     --  fingerprint of the certificate
        networks        --  networks listed in certificate
        unsafeNetworks  --  unsafeNetworks listed in certificate

    Modifiers:

        !=<exclusion>  --  omits entry if it matches the exclusion string
                           EXAMPLES:  "version:!=1", "curve:!=P256"
        ?              --  omits entry if blank
                           EXAMPLES:  "groups:?"
`)
	}
	flag.Parse()

	if !flags.Diff && !flags.Write && !flags.List {
		flags.Diff = true
	}

	return flags, flag.Args()
}

func main() {
	flags, paths := parseFlags()

	if flags.Version {
		info, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Println(info.Main.Version)
		} else {
			fmt.Println("v0.0.0-error")
		}
		return
	}

	if len(paths) == 0 {
		paths = []string{"."}
	}

	formatters, err := ParseFormatEntries(flags.Format)
	if err != nil {
		log.Fatal(err)
	}

	p := &processor{debug: flags.Debug, formatters: formatters, commentPrefix: flags.CommentPrefix}

	changed := false
	for _, path := range paths {
		err := filepath.WalkDir(path, func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("walk %q: %w", path, err)
			}
			if info.IsDir() {
				return nil
			}
			finfo, err := info.Info()
			if err != nil {
				return fmt.Errorf("info %q: %w", path, err)
			}
			if flags.LargeFileLimit > 0 && finfo.Size() > flags.LargeFileLimit {
				if p.debug {
					fmt.Fprintf(os.Stderr, "skipping large file: %q\n", path)
				}
				return nil
			}
			if info.Type()&fs.ModeSymlink != 0 {
				// TODO: follow symlinks?
				if p.debug {
					fmt.Fprintf(os.Stderr, "skipping symlink: %q\n", path)
				}
				return nil
			}

			found, err := p.processFile(path)
			if err != nil {
				return fmt.Errorf("process %q: %w", path, err)
			}
			if found {
				rs := diff.Diff(fmt.Sprintf("%s.orig", path), p.srcBuf.Bytes(), path, p.outBuf.Bytes())
				if len(rs) > 0 {
					changed = true
					if flags.List {
						fmt.Println(path)
					}
					if flags.Diff {
						_, err = os.Stdout.Write(rs)
						if err != nil {
							return fmt.Errorf("diff %q: %w", path, err)
						}
					}
					if flags.Write {
						err = write(path, &p.outBuf)
						if err != nil {
							return fmt.Errorf("write %q: %w", path, err)
						}
					}
				}
			}

			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	if changed && flags.Exit {
		os.Exit(1)
	}
}
