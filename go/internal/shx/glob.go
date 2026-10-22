package shx

import (
	"path/filepath"
	"sort"
)

// globSorted mirrors bash pathname expansion order (sorted names).
func globSorted(p string) ([]string, error) {
	m, err := filepath.Glob(p)
	sort.Strings(m)
	return m, err
}

// Glob mirrors bash glob expansion; with no match it returns the pattern
// itself, like bash without nullglob.
func Glob(p string) []string {
	m, _ := globSorted(p)
	if len(m) == 0 {
		return []string{p}
	}
	return m
}
