package domainlist

import (
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

const geoFile = "geosite.dat"
const maxGeoSize = 16 << 20

// GeoSiteList encodes repeated GeoSite messages (field 1). Each GeoSite has
// a tag (field 1) and repeated Domain messages (field 2). Keep only the
// requested groups, without pulling the V2Ray runtime into the resolver.
func walkFields(b []byte, visit func(protowire.Number, protowire.Type, []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		if err := visit(num, typ, b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func geoString(typ protowire.Type, b []byte) ([]byte, error) {
	if typ != protowire.BytesType {
		return nil, fmt.Errorf("invalid GeoSite field type %d", typ)
	}
	value, n := protowire.ConsumeBytes(b)
	if n < 0 {
		return nil, protowire.ParseError(n)
	}
	return value, nil
}

func (s *Set) addGeoDomain(b []byte) error {
	var kind uint64
	var value string
	err := walkFields(b, func(num protowire.Number, typ protowire.Type, data []byte) error {
		switch num {
		case 1:
			if typ != protowire.VarintType {
				return fmt.Errorf("invalid GeoSite domain type field")
			}
			kind, _ = protowire.ConsumeVarint(data)
		case 2:
			v, err := geoString(typ, data)
			value = string(v)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	kinds := [...]string{"keyword", "regexp", "domain", "full"}
	if kind >= uint64(len(kinds)) || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("invalid GeoSite domain %q of type %d", value, kind)
	}
	if !s.addRule(kinds[kind], value) {
		return fmt.Errorf("unusable GeoSite domain %q", value)
	}
	return nil
}

func (s *Set) loadGeo(path string, wanted map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxGeoSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxGeoSize {
		return fmt.Errorf("GeoSite exceeds %d bytes", maxGeoSize)
	}

	groups := 0
	seen := make(map[string]bool)
	err = walkFields(data, func(num protowire.Number, typ protowire.Type, raw []byte) error {
		if num != 1 {
			return nil
		}
		group, err := geoString(typ, raw)
		if err != nil {
			return err
		}
		var tag string
		domains := 0
		if err := walkFields(group, func(num protowire.Number, typ protowire.Type, raw []byte) error {
			switch num {
			case 1:
				v, err := geoString(typ, raw)
				tag = strings.ToUpper(string(v))
				return err
			case 2:
				if typ != protowire.BytesType {
					return fmt.Errorf("invalid GeoSite domain field")
				}
				domains++
			}
			return nil
		}); err != nil {
			return err
		}
		if tag == "" {
			return fmt.Errorf("invalid GeoSite group name %q", tag)
		}
		if domains > 0 {
			groups++
		}
		if !wanted[tag] || seen[tag] {
			return nil
		}
		if domains == 0 {
			return fmt.Errorf("empty GeoSite group %s", tag)
		}
		seen[tag] = true
		return walkFields(group, func(num protowire.Number, typ protowire.Type, raw []byte) error {
			if num != 2 {
				return nil
			}
			b, err := geoString(typ, raw)
			if err != nil {
				return err
			}
			if err := s.addGeoDomain(b); err != nil {
				return fmt.Errorf("GeoSite group %s: %w", tag, err)
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	if groups == 0 {
		return fmt.Errorf("no GeoSite groups found")
	}
	for tag := range wanted {
		if !seen[tag] {
			return fmt.Errorf("GeoSite group %s not found", tag)
		}
	}
	return nil
}

func validGeoTag(tag string) bool {
	if tag == "" || len(tag) > 128 {
		return false
	}
	for _, c := range tag {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '!') {
			return false
		}
	}
	return true
}

// CheckGeoSite validates a candidate file against the GeoSite tags in rules.
func CheckGeoSite(candidate, rules string) error {
	s := NewSet()
	wanted, err := s.loadRuleFile(rules)
	if err != nil {
		return err
	}
	return s.loadGeo(candidate, wanted)
}
