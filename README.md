# nebula-cert-comment

Modifies Nebula certificates found in files with a comment describing its
details. You can customize how the comment string is formatted.

## Example

```
# nebula: name="My CA" groups=dev notAfter=2026-06-11 fingerprint=0c0f34fa860f3d78fcd0fd4433d691591294a8eb114bfac599194fdb327f513a
-----BEGIN NEBULA CERTIFICATE-----
CjwKBU15IENBIgNkZXYo6ummwgYw6tCr0QY6IF0V5Tm6uQDe9OwuFTb1szohvig0
uBf0gZza7R5D4E9GQAESQO7exdDGgH1YqIoaPrD8/xNin0aqsIwbNtxfAcAdoq0P
t1t1YzB5/8PWCXmVsLwN1Gch2kyOLlkdbVozMIXiGA8=
-----END NEBULA CERTIFICATE-----
```

## Help

```
Usage: nebula-cert-comment [OPTION]... [FILE]...

  -comment string
    	prefix for comment lines (default "# nebula:")
  -d	display diffs
  -debug
    	log files we are skipping
  -e	exit(1) if changes needed/made
  -format string
    	The formatters to use for the comment (default "name,version:!=1,groups,notAfter,fingerprint")
  -l	list files whose comments need updating
  -large-file-limit int
    	don't process files larger than this in bytes, Set to 0 to disable (default 10000000)
  -w	write result to files


If none of "-d, -l, -w" are specified, defaults to "-d".

If a directory is specified for FILE, it is searched recursively. Symlinks are currently skipped.

Format string is a comma separated list of formatters with optional modifiers (separated by colons)

    Formatters:

        name         --  name of the certificate
        version      --  version of the certificate
        curve        --  curve of the certificate
        groups       --  comma separated list of groups defined on the certificate (omitted if empty)
        notAfter     --  expiration timestamp in UTC of the certificate, formatted as YYYY-MM-DD
        fingerprint  --  fingerprint of the certificate

    Modifiers:

        !=<exclusion>  --  omits entry if it matches the exclusion string
                           EXAMPLES:  "version:!=1", "curve:!=P256"
```
