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

func comment(outBuf, crtBuf *bytes.Buffer) error {
	c, _, err := cert.UnmarshalNebulaCertificateFromPEM(crtBuf.Bytes())
	if err != nil {
		return err
	}

	fmt.Fprintf(outBuf, "# nebula: name=%q", c.Details.Name)
	if len(c.Details.Groups) > 0 {
		fmt.Fprintf(outBuf, " groups=%s", strings.Join(c.Details.Groups, ","))
	}
	fp, err := c.Sha256Sum()
	if err != nil {
		return err
	}

	y, m, d := c.Details.NotAfter.UTC().Date()
	fmt.Fprintf(outBuf, " notAfter=%04d-%02d-%02d", y, m, d)
	fmt.Fprintf(outBuf, " fingerprint=%s\n", fp)

	return nil
}

func processFile(path string, srcBuf, outBuf, crtBuf *bytes.Buffer) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// _, err = srcBuf.ReadFrom(file)
	// if err != nil {
	// 	return false, err
	// }

	// Create a new scanner to read the file line by line
	reader := bufio.NewReader(file)

	// Loop through the file and read each line
	line := 1
	inCert := false
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

		_, err = srcBuf.Write(bs)
		if err != nil {
			return foundCert, err
		}

		// Check the first buffer for NUL, indicating a binary file
		if line == 1 {
			isBinary := bytes.IndexByte(bs, 0) != -1
			if isBinary {
				fmt.Fprintf(os.Stderr, "skipping binary file: %q\n", path)
				break
			}
		}

		text := string(bs)

		switch {
		case strings.HasPrefix(text, "-----BEGIN NEBULA CERTIFICATE-----"):
			inCert = true
			crtBuf.WriteString(text)
		case strings.HasPrefix(text, "-----END NEBULA CERTIFICATE-----"):
			inCert = false
			foundCert = true
			crtBuf.WriteString(text)

			err = comment(outBuf, crtBuf)
			if err != nil {
				return true, err
			}

			_, err = crtBuf.WriteTo(outBuf)
			if err != nil {
				return true, err
			}
			crtBuf.Reset()
		case strings.HasPrefix(text, "# nebula: name="):
			// Skip and regenerate
		default:
			if inCert {
				crtBuf.WriteString(text)
			} else {
				outBuf.WriteString(text)
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

	flagLargeFileLimit := flag.Int64("large-file-limit", 10*1000*1000, "don't process files larger than this in bytes, Set to 0 to disable")

	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	srcBuf := &bytes.Buffer{}
	outBuf := &bytes.Buffer{}
	crtBuf := &bytes.Buffer{}

	// tmpFile, err := os.CreateTemp("", "crt")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer os.Remove(tmpFile.Name()) // clean up

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
				fmt.Fprintf(os.Stderr, "skipping large file: %q\n", path)
				return nil
			}
			if info.Type()&fs.ModeSymlink != 0 {
				fmt.Fprintf(os.Stderr, "skipping symlink: %q\n", path)
				return nil
			}

			srcBuf.Reset()
			outBuf.Reset()
			crtBuf.Reset()
			found, err := processFile(path, srcBuf, outBuf, crtBuf)
			if err != nil {
				return fmt.Errorf("process %q: %w", path, err)
			}
			if found {
				if *flagList {
					fmt.Println(path)
				}
				if *flagDiff {
					rs := diff.Diff(fmt.Sprintf("%s.orig", path), srcBuf.Bytes(), path, outBuf.Bytes())
					if len(rs) > 0 {
						_, err = os.Stdout.Write(rs)
						if err != nil {
							return fmt.Errorf("diff %q: %w", path, err)
						}
					}
				}
				if *flagWrite {
					err = write(path, outBuf)
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
