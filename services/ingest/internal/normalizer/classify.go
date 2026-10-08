package normalizer

import (
	"fmt"

	"github.com/beenuar/aisoc/services/ingest/internal/eventcatalog"
)

// Event classification, from the catalogue loaded at boot.
//
// The catalogue maps a vendor's own event type onto a normalized action, a
// sensitivity and an optional ATT&CK hint. This attaches the answer to the
// event so the lake, the detection matcher and triage read one
// classification rather than each re-deriving a meaning from the event name.
//
// It deliberately changes nothing else on the event. Sensitivity is a
// property of the event *class*; the vendor's severity on the record and the
// OCSF class still decide whether fusion promotes it. A `critical`
// sensitivity that forced an alert would let a one-line edit to a data file
// flood a queue.

// eventClassification is what lands on the event.
type eventClassification struct {
	// Source and EventType are carried so a reader of the lake row can
	// check the classification against the catalogue without the raw
	// payload, and so a hunt can group by the vendor's own vocabulary.
	Source      string   `json:"source"`
	EventType   string   `json:"event_type"`
	Action      string   `json:"action"`
	Sensitivity string   `json:"sensitivity"`
	ATTACK      []string `json:"attack,omitempty"`
}

// classify returns the classification for this event, or a warning
// explaining why there is none.
//
// Three outcomes, and the distinction is the point:
//
//   - a hit, which lands on the event;
//   - a type the catalogue lists as deliberately unclassified, or a source
//     with no catalogue at all, both of which are silent: somebody has
//     already decided, or nobody has started, and neither is news;
//   - a type this source's catalogue has never seen, which is a warning on
//     the event. That is the only case an operator can act on, and it is how
//     the catalogue learns it has fallen behind the vendor.
func (n *Normalizer) classify(connectorType string, payload map[string]interface{}) (*eventClassification, string) {
	declaredPath, hasCatalog := n.catalog.EventTypePath(connectorType)
	if !hasCatalog {
		return nil, ""
	}

	// The vendor's record, which for a canonical envelope is nested under
	// `raw_event`. The key is `raw_event` and never `raw`: 26 connectors
	// once emitted `raw`, missed the canonical-envelope check and fell
	// through to a borrowed vendor profile.
	record := payload
	if nested, ok := payload["raw_event"].(map[string]interface{}); ok {
		record = nested
	}

	eventType, found := eventcatalog.EventType(record, declaredPath)
	if !found {
		// The source has a catalogue and this record carries nothing at
		// the declared path. Not a warning: several connectors emit shapes
		// that genuinely have no event type, and warning on each would
		// make the field unreadable.
		return nil, ""
	}

	classification, status := n.catalog.Lookup(connectorType, eventType)
	switch status {
	case eventcatalog.StatusClassified:
		return &eventClassification{
			Source:      connectorType,
			EventType:   eventType,
			Action:      classification.Action,
			Sensitivity: string(classification.Sensitivity),
			ATTACK:      classification.ATTACK,
		}, ""
	case eventcatalog.StatusUnknown:
		return nil, fmt.Sprintf(
			"event type %q is not in the %s event catalogue: it is neither classified nor recorded as "+
				"deliberately unclassified, so nothing downstream knows how sensitive it is "+
				"(schemas/event_catalog/%s.yaml)",
			eventType, connectorType, connectorType,
		)
	}
	return nil, ""
}
