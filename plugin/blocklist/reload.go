package blocklist

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"
)

const defaultRuleDir = "/etc/coredns/adblock"
const defaultReload = 10 * time.Second

var reloadLog = log.NewWithPlugin("blocklist")

type ruleFile struct {
	path  string
	allow bool
}
type ruleSet struct {
	files   []ruleFile
	current atomic.Pointer[filter]
	stamps  []os.FileInfo // exclusively owned by the loader
}

func resolvePath(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func (s *ruleSet) stat() ([]os.FileInfo, error) {
	stamps := make([]os.FileInfo, len(s.files))
	for i, f := range s.files {
		info, err := os.Stat(f.path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", f.path)
		}
		stamps[i] = info
	}
	return stamps, nil
}

func sameFiles(a, b []os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if !os.SameFile(x, y) || x.Size() != y.Size() || !x.ModTime().Equal(y.ModTime()) {
			return false
		}
	}
	return true
}

func (s *ruleSet) reload() error {
	before, err := s.stat()
	if err != nil {
		return err
	}
	if sameFiles(before, s.stamps) {
		return nil
	}
	f := new(filter)
	for _, file := range s.files {
		if _, err := f.load(file.path, file.allow); err != nil {
			return fmt.Errorf("load %s: %w", file.path, err)
		}
	}
	after, err := s.stat()
	if err != nil {
		return err
	}
	if !sameFiles(before, after) {
		return fmt.Errorf("rule files changed while loading")
	}
	s.current.Store(f)
	s.stamps = after
	return nil
}

func (s *ruleSet) watch(interval time.Duration, stop <-chan struct{}) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	lastError := ""
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if err := s.reload(); err != nil {
				if msg := err.Error(); msg != lastError {
					reloadLog.Warningf("keeping previous rules: %v", err)
					lastError = msg
				}
			} else {
				lastError = ""
			}
		}
	}
}
