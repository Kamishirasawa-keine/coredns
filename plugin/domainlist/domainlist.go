// Package domainlist matches DNS names against categories from geosite.dat.
// Rule files contain one geosite:<category> reference per line, with optional
// # comments. The database lives alongside the rule file.
package domainlist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Set is an immutable snapshot of one or more rule files. All lookups are
// read-only, so a Set can be shared between goroutines without locking.
type Set struct {
	exact   map[string]struct{}
	suffix  map[string]struct{}
	keyword []string
	res     []*regexp.Regexp

	rejected  int // lines that were recognised but not usable
	total     int // rules accepted
	geoLoaded map[string]bool
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{
		exact:  make(map[string]struct{}),
		suffix: make(map[string]struct{}),
	}
}

// Rules returns the number of accepted rules.
func (s *Set) Rules() int { return s.total }

// Rejected returns the number of lines that were dropped.
func (s *Set) Rejected() int { return s.rejected }

// Match reports whether qname belongs to the set. qname is a presentation
// format name, with or without the trailing root dot.
func (s *Set) Match(qname string) bool {
	if s == nil {
		return false
	}
	name := normalize(qname)
	if name == "" {
		return false
	}

	if len(s.exact) != 0 {
		if _, ok := s.exact[name]; ok {
			return true
		}
	}

	if len(s.suffix) != 0 {
		if _, ok := s.suffix[name]; ok {
			return true
		}
		// Walk every label boundary and look the remainder up.
		for i := 0; i < len(name); i++ {
			if name[i] == '.' {
				if _, ok := s.suffix[name[i+1:]]; ok {
					return true
				}
			}
		}
	}

	for _, kw := range s.keyword {
		if strings.Contains(name, kw) {
			return true
		}
	}
	for _, re := range s.res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func (s *Set) addRule(kind, line string) bool {
	switch kind {
	case "regexp":
		line = strings.TrimSpace(line)
		if line == "" {
			return false
		}
		re, err := regexp.Compile("(?i)" + line)
		if err != nil {
			s.rejected++
			return false
		}
		s.res = append(s.res, re)
		s.total++
		return true

	case "keyword":
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			return false
		}
		s.keyword = append(s.keyword, line)
		s.total++
		return true
	}

	line = normalize(line)
	// A domain never contains a path, a wildcard or whitespace; such lines are
	// either junk or belong to the wildcard form handled by regexp above.
	if line == "" || strings.ContainsAny(line, "/*| \t\"'") {
		s.rejected++
		return false
	}

	if kind == "full" {
		if _, dup := s.exact[line]; !dup {
			s.exact[line] = struct{}{}
			s.total++
		}
		return true
	}
	if _, dup := s.suffix[line]; !dup {
		s.suffix[line] = struct{}{}
		s.total++
	}
	return true
}

func normalize(name string) string {
	name = strings.TrimSpace(name)
	if n := len(name); n > 0 && name[n-1] == '.' {
		name = name[:n-1]
	}
	if name == "" {
		return ""
	}
	// Fast path: by far most queries are already lowercase.
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			return strings.ToLower(name)
		}
	}
	return name
}

// LoadFile reads one rule file into the set.
func (s *Set) LoadFile(path string) error {
	wanted, err := s.loadRuleFile(path)
	if err != nil || len(wanted) == 0 {
		return err
	}
	geo := filepath.Join(filepath.Dir(path), geoFile)
	if s.geoLoaded == nil {
		s.geoLoaded = make(map[string]bool)
	}
	// A fresh install may not have downloaded its first database yet.
	if err := s.loadGeo(geo, wanted); err != nil {
		if os.IsNotExist(err) {
			s.geoLoaded[geo] = false
			return nil
		}
		return fmt.Errorf("load %s: %w", geo, err)
	}
	s.geoLoaded[geo] = true
	return nil
}

func (s *Set) loadRuleFile(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	wanted := make(map[string]bool)
	sc := bufio.NewScanner(f)
	// Rule files are line based; 1 MiB is far beyond any real rule.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "geosite:") {
			return nil, fmt.Errorf("%s:%d: expected geosite:<category>", path, lineNo)
		}
		tag := strings.ToUpper(strings.TrimSpace(line[len("geosite:"):]))
		if !validGeoTag(tag) {
			return nil, fmt.Errorf("%s:%d: invalid GeoSite reference %q", path, lineNo, line)
		}
		wanted[tag] = true
	}
	return wanted, sc.Err()
}

// LoadFiles reads every path into a fresh Set. Any unreadable file is a hard
// error: a partially loaded set silently misroutes traffic, which is worse
// than refusing to start.
func LoadFiles(paths []string) (*Set, error) {
	s := NewSet()
	if len(paths) == 0 {
		return s, fmt.Errorf("no rule files configured")
	}
	for _, p := range paths {
		if err := s.LoadFile(p); err != nil {
			return nil, fmt.Errorf("failed to load rule file %q: %w", p, err)
		}
	}
	return s, nil
}

type stamp struct {
	size  int64
	mtime time.Time
}

func statAll(paths []string) ([]stamp, error) {
	out := make([]stamp, len(paths))
	for i, p := range paths {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			out[i].size = -1
			continue
		}
		if err != nil {
			return nil, err
		}
		out[i] = stamp{size: fi.Size(), mtime: fi.ModTime()}
	}
	return out, nil
}

// FileSet is a Set that reloads itself when its files change on disk, so a
// rule update does not require restarting the resolver.
type FileSet struct {
	paths    []string
	interval time.Duration

	cur atomic.Pointer[Set]

	mu     sync.Mutex // guards stamps
	stamps []stamp

	onReload func(*Set)
	warn     func(format string, args ...interface{})
}

// NewFileSet returns a FileSet over paths. interval <= 0 disables reloading.
func NewFileSet(paths []string, interval time.Duration, warn func(string, ...interface{})) *FileSet {
	if warn == nil {
		warn = func(string, ...interface{}) {}
	}
	return &FileSet{paths: paths, interval: interval, warn: warn}
}

// Load performs the initial read. It is a hard error: the caller should fail
// startup rather than serve with an empty set.
func (f *FileSet) Load() (*Set, error) {
	st, err := statAll(f.watchPaths())
	if err != nil {
		return nil, err
	}
	set, err := LoadFiles(f.paths)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.stamps = st
	f.mu.Unlock()
	f.cur.Store(set)
	return set, nil
}

// Set returns the current snapshot, or nil before the first Load.
func (f *FileSet) Set() *Set { return f.cur.Load() }

// Match reports whether qname is in the current set.
func (f *FileSet) Match(qname string) bool { return f.cur.Load().Match(qname) }

// OnReload registers a callback fired after every successful reload.
func (f *FileSet) OnReload(fn func(*Set)) { f.onReload = fn }

// Watch polls the rule files until ctx is cancelled.
func (f *FileSet) Watch(stop <-chan struct{}) {
	if f.interval <= 0 {
		return
	}
	go func() {
		tk := time.NewTicker(f.interval)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				f.reloadIfChanged()
			}
		}
	}()
}

func (f *FileSet) watchPaths() []string {
	paths := append([]string(nil), f.paths...)
	seen := make(map[string]bool)
	for _, path := range f.paths {
		geo := filepath.Join(filepath.Dir(path), geoFile)
		if !seen[geo] {
			paths = append(paths, geo)
			seen[geo] = true
		}
	}
	return paths
}

func (f *FileSet) reloadIfChanged() {
	cur, err := statAll(f.watchPaths())
	if err != nil {
		f.warn("stat rule files: %v (keeping the loaded set)", err)
		return
	}
	f.mu.Lock()
	same := len(cur) == len(f.stamps)
	if same {
		for i := range cur {
			if cur[i] != f.stamps[i] {
				same = false
				break
			}
		}
	}
	f.mu.Unlock()
	if same {
		return
	}

	old := f.cur.Load()
	set, err := LoadFiles(f.paths)
	if err != nil {
		// Keep serving the previous snapshot; a broken download must not
		// turn into an empty rule set.
		f.warn("reload rule files: %v (keeping %d rules)", err, old.Rules())
		return
	}
	for path, loaded := range set.geoLoaded {
		if !loaded && old.geoLoaded[path] {
			f.warn("GeoSite %s disappeared (keeping %d rules)", path, old.Rules())
			return
		}
	}
	f.mu.Lock()
	f.stamps = cur
	f.mu.Unlock()
	f.cur.Store(set)
	f.warn("reloaded rule files: %d rules (%d rejected)", set.Rules(), set.Rejected())
	if f.onReload != nil {
		f.onReload(set)
	}
}
