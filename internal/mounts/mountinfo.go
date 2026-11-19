// Package mounts parses /proc/<pid>/mountinfo and answers the only question
// layerclue needs from it: which mount actually serves a given logical path.
//
// mountinfo escapes spaces, tabs, newlines and backslashes as octal sequences
// (\040, \011, \012, \134). Parsing before decoding is a classic source of
// wrong mount points, so decoding happens as each field is read.
package mounts

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Entry is one line of mountinfo.
type Entry struct {
	ID           int
	ParentID     int
	Major        int
	Minor        int
	Root         string
	Point        string
	Options      []string
	Optional     []string
	FSType       string
	Source       string
	SuperOptions []string
	Line         int
}

// Table is the mount table of a mount namespace.
type Table []Entry

// Parse reads a mountinfo stream.
func Parse(r io.Reader) (Table, error) {
	var table Table
	ids := make(map[int]bool)
	total := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		total += len(sc.Bytes()) + 1
		if total > 16<<20 || len(table) >= 8192 {
			return nil, errors.New("mountinfo processing limit exceeded")
		}
		text := strings.TrimSpace(sc.Text())
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return nil, errors.New("mountinfo contains unsupported bytes")
		}
		if text == "" {
			continue
		}
		e, err := parseLine(text)
		if err != nil {
			return nil, fmt.Errorf("mountinfo:%d: %w", line, err)
		}
		e.Line = line
		if ids[e.ID] {
			return nil, fmt.Errorf("duplicate mount id %d", e.ID)
		}
		ids[e.ID] = true
		table = append(table, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return table, nil
}

// ParseFile reads a mountinfo file from disk.
func ParseFile(name string) (Table, error) {
	// #nosec G304 -- Trusted lab/test convenience for explicitly selected mountinfo, including procfs. Incident CLI input uses evidence.OpenRegular instead.
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func parseLine(s string) (Entry, error) {
	fields := strings.Fields(s)
	sep := -1
	for i, f := range fields {
		if f == "-" {
			sep = i
			break
		}
	}
	if sep < 6 || len(fields) != sep+4 {
		return Entry{}, errors.New("malformed mountinfo line")
	}

	var e Entry
	var err error
	if e.ID, err = strconv.Atoi(fields[0]); err != nil {
		return Entry{}, fmt.Errorf("mount id: %w", err)
	}
	if e.ParentID, err = strconv.Atoi(fields[1]); err != nil {
		return Entry{}, fmt.Errorf("parent id: %w", err)
	}
	major, minor, ok := strings.Cut(fields[2], ":")
	if e.ID <= 0 || e.ParentID < 0 {
		return Entry{}, errors.New("invalid mount identifiers")
	}
	if !ok {
		return Entry{}, fmt.Errorf("malformed device %q", fields[2])
	}
	if e.Major, err = strconv.Atoi(major); err != nil {
		return Entry{}, fmt.Errorf("device major: %w", err)
	}
	if e.Minor, err = strconv.Atoi(minor); err != nil {
		return Entry{}, fmt.Errorf("device minor: %w", err)
	}
	if e.Major < 0 || e.Minor < 0 {
		return Entry{}, errors.New("invalid device numbers")
	}
	// Escapes can introduce NUL or invalid UTF-8 even when the encoded line
	// passed the initial byte check. Validate every decoded field before use.
	for _, field := range fields {
		decoded := Unescape(field)
		if !utf8.ValidString(decoded) || strings.ContainsRune(decoded, 0) {
			return Entry{}, errors.New("decoded mountinfo field contains unsupported bytes")
		}
	}

	e.Root = Unescape(fields[3])
	e.Point = path.Clean(Unescape(fields[4]))
	// Namespace pseudo-files have kernel-generated roots such as net:[123],
	// rather than ordinary absolute filesystem paths.
	validRoot := strings.HasPrefix(e.Root, "/") || Unescape(fields[sep+1]) == "nsfs" && namespaceRoot(e.Root)
	if !validRoot || !strings.HasPrefix(e.Point, "/") || len(e.Point) > 4096 || len(e.Root) > 4096 {
		return Entry{}, errors.New("mount paths/root descriptors must be valid and bounded")
	}
	e.Options = splitOptions(fields[5])
	for _, f := range fields[6:sep] {
		e.Optional = append(e.Optional, Unescape(f))
	}
	e.FSType = Unescape(fields[sep+1])
	e.Source = Unescape(fields[sep+2])
	if len(e.Source) > 4096 {
		return Entry{}, errors.New("mount source exceeds path budget")
	}
	if len(fields) > sep+3 {
		e.SuperOptions = splitOptions(fields[sep+3])
	}
	if e.FSType == "overlay" {
		seen := map[string]bool{}
		for _, option := range e.SuperOptions {
			key, value, _ := strings.Cut(option, "=")
			if key != "lowerdir" && key != "upperdir" && key != "workdir" {
				continue
			}
			if seen[key] || (len(value)-len(strings.TrimRight(value, `\`)))%2 != 0 {
				return Entry{}, errors.New("ambiguous or unterminated OverlayFS path option")
			}
			seen[key] = true
		}
	}
	return e, nil
}

// Split the encoded delimiters first: a decoded \054 is part of a value,
// never a new mount option. OverlayFS path escaping is a separate second layer.
func splitOptions(encoded string) []string {
	options := strings.Split(encoded, ",")
	for i := range options {
		options[i] = Unescape(options[i])
	}
	return options
}

func namespaceRoot(root string) bool {
	kind, number, ok := strings.Cut(root, ":[")
	if !ok || !strings.HasSuffix(number, "]") {
		return false
	}
	switch kind {
	case "net", "mnt", "pid", "pid_for_children", "user", "uts", "ipc", "cgroup", "time", "time_for_children":
	default:
		return false
	}
	number = strings.TrimSuffix(number, "]")
	inode, err := strconv.ParseUint(number, 10, 64)
	return err == nil && inode > 0 && strconv.FormatUint(inode, 10) == number
}

// Unescape decodes the octal escapes mountinfo uses for whitespace and
// backslashes.
func Unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if s[i+1] == '\\' {
			b.WriteByte('\\')
			i++
			continue
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String()
}

// Deepest is a compatibility wrapper. Ambiguous topology fails closed.
func (t Table) Deepest(logicalPath string) (Entry, string, bool) {
	e, rel, err := t.Select(logicalPath)
	return e, rel, err == nil
}

// Select walks parent IDs, not line order. A mount over a directory hides
// children attached to the previous mount, even if their paths are longer.
func (t Table) Select(logicalPath string) (Entry, string, error) {
	p := path.Clean("/" + logicalPath)
	byID := make(map[int]Entry, len(t))
	children := make(map[int][]Entry)
	rootParents := make(map[int]bool)
	for _, e := range t {
		if _, ok := byID[e.ID]; ok {
			return Entry{}, "", errors.New("duplicate mount id")
		}
		byID[e.ID] = e
		children[e.ParentID] = append(children[e.ParentID], e)
		if e.Point == "/" && e.ParentID != e.ID {
			rootParents[e.ParentID] = true
		}
	}
	var current Entry
	for _, e := range t {
		if e.Point == "/" && !rootParents[e.ID] {
			if current.ID != 0 {
				return Entry{}, "", errors.New("ambiguous namespace root")
			}
			current = e
		}
	}
	if current.ID == 0 {
		return Entry{}, "", errors.New("mount namespace has no visible root")
	}
	seen := make(map[int]bool)
	for {
		if seen[current.ID] {
			return Entry{}, "", errors.New("cycle in mount topology")
		}
		seen[current.ID] = true
		var next Entry
		for _, child := range children[current.ID] {
			if child.ID == current.ID {
				continue
			}
			if !covers(current.Point, child.Point) {
				return Entry{}, "", errors.New("inconsistent mount parent")
			}
			if !covers(child.Point, p) {
				continue
			}
			if next.ID == 0 || len(child.Point) < len(next.Point) {
				next = child
			} else if len(child.Point) == len(next.Point) {
				return Entry{}, "", errors.New("ambiguous mounts at the same point")
			}
		}
		if next.ID == 0 {
			break
		}
		current = next
	}
	for _, e := range t {
		if e.Point != "/" && covers(e.Point, p) {
			if _, ok := byID[e.ParentID]; !ok {
				return Entry{}, "", fmt.Errorf("missing parent for mount %d", e.ID)
			}
		}
	}
	rel := strings.TrimPrefix(p, current.Point)
	if rel == "" {
		rel = "/"
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return current, rel, nil
}

func covers(mount, p string) bool {
	return mount == "/" || p == mount || strings.HasPrefix(p, mount+"/")
}

// HasOption reports whether the mount was performed with the given flag.
func (e Entry) HasOption(flag string) bool {
	for _, o := range e.Options {
		if o == flag {
			return true
		}
	}
	return false
}

// SuperValue returns the value of a comma separated super-block option.
func (e Entry) SuperValue(key string) string {
	prefix := key + "="
	for _, o := range e.SuperOptions {
		if strings.HasPrefix(o, prefix) {
			value := strings.TrimPrefix(o, prefix)
			if e.FSType == "overlay" && (key == "upperdir" || key == "workdir") {
				return overlayPath(value)
			}
			return value
		}
	}
	return ""
}

// LowerDirs splits the overlayfs lowerdir option into layer directories,
// topmost first.
//
// Overlayfs separates layers with ':' and allows an escaped "\:" inside a
// path, so a naive split is wrong for any layer path containing a colon.
func (e Entry) LowerDirs() []string {
	v := e.SuperValue("lowerdir")
	if v == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] == '\\' && i+1 < len(v):
			cur.WriteByte(v[i+1])
			i++
		case v[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(v[i])
		}
	}
	out = append(out, cur.String())
	return out
}

func overlayPath(value string) string {
	var path strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
		}
		path.WriteByte(value[i])
	}
	return path.String()
}
