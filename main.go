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
	"strings"

	"github.com/slackhq/nebula/cert"
	"github.com/wadey/nebula-cert-comment/internal/diff"
)

type processor struct {
	debug bool

	// buffer for original source file bytes
	srcBuf bytes.Buffer

	// buffer for output file bytes
	outBuf bytes.Buffer

	// buffer for trimmed certificate block bytes
	crtBuf bytes.Buffer

	// buffer for raw certificate block bytes
	crtRaw bytes.Buffer
}

func comment(outBuf, crtBuf *bytes.Buffer) error {
	c, _, err := cert.UnmarshalCertificateFromPEM(crtBuf.Bytes())
	if err != nil {
		return err
	}

	fmt.Fprintf(outBuf, "# nebula: name=%q", c.Name())
	if c.Version() > 1 {
		fmt.Fprintf(outBuf, " version=%d", c.Version())
	}
	if len(c.Groups()) > 0 {
		fmt.Fprintf(outBuf, " groups=%s", strings.Join(c.Groups(), ","))
	}
	fp, err := c.Fingerprint()
	if err != nil {
		return err
	}

	y, m, d := c.NotAfter().UTC().Date()
	fmt.Fprintf(outBuf, " notAfter=%04d-%02d-%02d", y, m, d)
	fmt.Fprintf(outBuf, " fingerprint=%s\n", fp)

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

	// Create a new scanner to read the file line by line
	reader := bufio.NewReader(file)

	// Loop through the file and read each line
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
		case strings.HasPrefix(trimText, "-----BEGIN NEBULA CERTIFICATE-----"):
			if text[0] != '-' {
				s := strings.SplitN(text, "-", 2)
				certPad = s[0]
			}
			inCert = true
			p.crtBuf.WriteString(strings.TrimPrefix(text, certPad))
			p.crtRaw.WriteString(text)
		case strings.HasPrefix(trimText, "-----END NEBULA CERTIFICATE-----"):
			p.crtBuf.WriteString(strings.TrimPrefix(text, certPad))
			p.crtRaw.WriteString(text)

			p.outBuf.WriteString(certPad)
			// p.crtBuf.WriteTo(os.Stderr)
			err = comment(&p.outBuf, &p.crtBuf)
			if err != nil {
				return true, err
			}

			_, err = p.crtRaw.WriteTo(&p.outBuf)
			if err != nil {
				return true, err
			}
			p.crtBuf.Reset()
			p.crtRaw.Reset()

			certPad = ""
			inCert = false
			foundCert = true
		case strings.HasPrefix(trimText, "# nebula: name="):
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

func main() {
	flagDiff := flag.Bool("d", false, "display diffs")
	flagWrite := flag.Bool("w", false, "write result to files")
	flagList := flag.Bool("l", false, "list files whose comments need updating")
	flagDebug := flag.Bool("debug", false, "log files we are skipping")

	flagLargeFileLimit := flag.Int64("large-file-limit", 10*1000*1000, "don't process files larger than this in bytes, Set to 0 to disable")

	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	p := &processor{debug: *flagDebug}

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
			if *flagLargeFileLimit > 0 && finfo.Size() > *flagLargeFileLimit {
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
				if *flagList {
					fmt.Println(path)
				}
				if *flagDiff {
					rs := diff.Diff(fmt.Sprintf("%s.orig", path), p.srcBuf.Bytes(), path, p.outBuf.Bytes())
					if len(rs) > 0 {
						_, err = os.Stdout.Write(rs)
						if err != nil {
							return fmt.Errorf("diff %q: %w", path, err)
						}
					}
				}
				if *flagWrite {
					err = write(path, &p.outBuf)
					if err != nil {
						return fmt.Errorf("write %q: %w", path, err)
					}
				}
			}

			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}
}
