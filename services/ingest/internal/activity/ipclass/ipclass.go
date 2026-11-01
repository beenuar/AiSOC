// Package ipclass answers one question about a public address, offline:
// is it a Tor exit relay, a hosting range, a VPN, a public proxy or a
// residential proxy?
//
// Why it is here and not behind a lookup service
// ----------------------------------------------
// The depth plan's rule is explicit: no per-event network call. The IP
// enricher one directory up already reaches `services/enrichment` for
// geography and ASN, and that service is `full`-profile only, so a CORE
// install gets no geography at all. A class that only exists on `full`
// would make every detection reading it silently dead on the smallest
// deployment, which is the defect shape this repository keeps finding.
// So the dataset is pinned, committed and embedded in the binary, and the
// lookup is a binary search over sorted ranges.
//
// What "absent" means
// -------------------
// An address with no entry carries no class. It does not carry "not a
// VPN". Three of the five classes ship with zero records (see the dataset
// manifest), so a false negative is the normal case and must stay legible
// as one: a rule asking for `ip_class: vpn` finds nothing on a deployment
// that supplied no VPN list, and that is honest. A boolean `is_vpn: false`
// would be a claim the dataset cannot support.
//
// The version travels with the answer
// -----------------------------------
// Every stamp carries the dataset version. A class with no version is a
// claim nobody can date, and this dataset is refreshed: an address that was
// a Tor exit in March is not necessarily one in November, and an analyst
// re-reading a six-month-old alert needs to know which snapshot said so.
package ipclass

import (
	"bufio"
	"embed"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

//go:embed data/ip_classes.tsv data/manifest.json
var datasetFS embed.FS

// Classification is one answer. Empty `Class` means the dataset had no
// entry, which is distinct from "the dataset says it is ordinary".
type Classification struct {
	Class    string
	Provider string
	Version  string
}

type entry struct {
	prefix   netip.Prefix
	class    string
	provider string
}

type table struct {
	// v4 and v6 kept apart: comparing a 4-byte and a 16-byte address in one
	// sorted slice needs a total order across families that netip does not
	// give, and faking one with 4-in-6 mapping puts ::ffff:0:0/96 in the
	// middle of the IPv4 space.
	v4      []entry
	v6      []entry
	version string
}

var (
	loadOnce sync.Once
	loaded   *table
)

func get() *table {
	loadOnce.Do(func() { loaded = load() })
	return loaded
}

func load() *table {
	t := &table{}

	if blob, err := datasetFS.ReadFile("data/manifest.json"); err == nil {
		var manifest struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(blob, &manifest) == nil {
			t.version = manifest.Version
		}
	}

	file, err := datasetFS.Open("data/ip_classes.tsv")
	if err != nil {
		return t
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}
		e := entry{prefix: prefix.Masked(), class: parts[1], provider: parts[2]}
		if prefix.Addr().Is4() {
			t.v4 = append(t.v4, e)
		} else {
			t.v6 = append(t.v6, e)
		}
	}

	// The file is written sorted, but sorting here rather than trusting it
	// means a hand-edited or partially-written dataset degrades to a wrong
	// answer for one prefix instead of to a broken binary search for every
	// address after it.
	sortEntries(t.v4)
	sortEntries(t.v6)
	return t
}

func sortEntries(entries []entry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].prefix.Addr().Less(entries[j].prefix.Addr())
	})
}

// Version is the pinned dataset's version string, for surfaces that report
// which snapshot is loaded without classifying anything.
func Version() string { return get().version }

// Size is the number of records loaded. A gate uses it to refuse a build
// whose embedded dataset is empty.
func Size() int {
	t := get()
	return len(t.v4) + len(t.v6)
}

// Lookup classifies one address. The caller is responsible for having
// decided the address is public; this package does not re-implement that
// predicate, because two copies of "is this worth looking up" is exactly
// how the enricher beside it would come to disagree with its own gate.
func Lookup(raw string) (Classification, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return Classification{}, false
	}
	addr = addr.Unmap()

	t := get()
	entries := t.v4
	if !addr.Is4() {
		entries = t.v6
	}
	if len(entries) == 0 {
		return Classification{}, false
	}

	// Entries may nest (a /32 Tor relay inside a /16 cloud range), so the
	// first candidate at or below the address is not necessarily the match.
	// Walk back over entries whose network address is <= the query until one
	// contains it. The dataset's deepest nesting is shallow, so this is a
	// handful of comparisons, not a scan.
	idx := sort.Search(len(entries), func(i int) bool {
		return addr.Less(entries[i].prefix.Addr())
	})
	for i := idx - 1; i >= 0 && i >= idx-maxNestingProbe; i-- {
		if entries[i].prefix.Contains(addr) {
			return Classification{
				Class:    entries[i].class,
				Provider: entries[i].provider,
				Version:  t.version,
			}, true
		}
	}
	return Classification{}, false
}

// maxNestingProbe bounds the walk-back. A /8 containing many /24s would
// otherwise make the walk linear in the enclosing range's sibling count.
// 64 covers every nesting depth the shipped dataset has; a deeper one is a
// miss rather than a slow scan, and the dataset gate reports nesting depth
// so a future snapshot that needs more says so instead of silently losing
// matches.
const maxNestingProbe = 64

// SampleAddressForClass returns one address the dataset classifies as
// `class`, for tests that must not hardcode an address a refresh will move.
// Empty when the shipped dataset has no record for the class, which is the
// correct answer for the three tenant-supplied-only classes.
func SampleAddressForClass(class string) string {
	t := get()
	for _, group := range [][]entry{t.v4, t.v6} {
		for _, e := range group {
			if e.class == class {
				return e.prefix.Addr().String()
			}
		}
	}
	return ""
}
