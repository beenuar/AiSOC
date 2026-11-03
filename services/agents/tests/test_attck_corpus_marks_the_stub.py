"""``/health`` says which ATT&CK corpus its technique count describes.

A default install has no STIX bundle on disk and does not fetch one (the CDN
leg is opt-in, see ``_cdn_fetch_enabled``), so it runs the built-in stub.
``GET /health`` published ``attck_corpus: {"total_techniques": 14}`` with no
marker of any kind — fourteen of ATT&CK Enterprise's ~670, in the same shape
a complete corpus would be reported. The log line beside it was already
correct, which is the tell: two surfaces describing one fact, and only the
one a human reads said what it was.

These tests pin the marker rather than the number, because the stub's size is
allowed to change and its *identity* is not.
"""

from __future__ import annotations

import unittest

from app.tools import mitre_full


class AttckCorpusProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = (
            dict(mitre_full._techniques),
            dict(mitre_full._actors),
            dict(mitre_full._tactic_map),
            mitre_full._loaded,
            mitre_full._load_time,
            mitre_full._source,
        )
        mitre_full._techniques.clear()
        mitre_full._actors.clear()
        mitre_full._tactic_map.clear()
        mitre_full._loaded = False
        mitre_full._load_time = 0.0
        mitre_full._source = None

    def tearDown(self) -> None:
        techniques, actors, tactics, loaded, load_time, source = self._saved
        mitre_full._techniques.clear()
        mitre_full._techniques.update(techniques)
        mitre_full._actors.clear()
        mitre_full._actors.update(actors)
        mitre_full._tactic_map.clear()
        mitre_full._tactic_map.update(tactics)
        mitre_full._loaded = loaded
        mitre_full._load_time = load_time
        mitre_full._source = source

    def test_nothing_loaded_is_its_own_state(self) -> None:
        """Zero techniques from "not loaded yet" must not read as a corpus."""
        summary = mitre_full.get_coverage_summary()
        self.assertIsNone(summary["source"])
        self.assertFalse(summary["is_stub"])
        self.assertFalse(summary["corpus_loaded"])
        self.assertIn("describe nothing", summary["detail"])

    def test_stub_corpus_is_marked_as_a_stub(self) -> None:
        mitre_full._load_stub_corpus()
        summary = mitre_full.get_coverage_summary()

        self.assertTrue(summary["corpus_loaded"])
        self.assertTrue(summary["is_stub"], "a default install runs the stub and /health must say so")
        self.assertEqual(mitre_full.SOURCE_STUB, summary["source"])
        self.assertIn("not the full ATT&CK Enterprise matrix", summary["detail"])
        # The remedy belongs with the diagnosis, or the marker is just a label.
        self.assertIn("AISOC_ATTCK_CDN_FETCH=1", summary["detail"])
        self.assertGreater(summary["total_techniques"], 0)

    def test_full_bundle_is_not_marked_as_a_stub(self) -> None:
        """The positive control: a real bundle must clear the flag.

        Without this, a marker stuck permanently on would pass every test
        above while being exactly as wrong in the other direction.
        """
        mitre_full._parse_stix_bundle(
            {
                "objects": [
                    {
                        "id": "x-mitre-tactic--0",
                        "type": "x-mitre-tactic",
                        "x_mitre_shortname": "execution",
                        "name": "Execution",
                        "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
                    },
                    {
                        "id": "attack-pattern--0",
                        "type": "attack-pattern",
                        "name": "Command and Scripting Interpreter",
                        "description": "",
                        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059", "url": ""}],
                    },
                ]
            }
        )
        summary = mitre_full.get_coverage_summary()

        self.assertFalse(summary["is_stub"])
        self.assertEqual(mitre_full.SOURCE_FULL, summary["source"])
        self.assertIn("Full ATT&CK Enterprise corpus", summary["detail"])


if __name__ == "__main__":
    unittest.main()
