# Sandbox provider fixtures

Two kinds of payload live here and they are not equally trustworthy, so they
are labelled rather than mixed.

## Recorded

`malwareanalyzer_report_eicar.json`

Captured from `GET https://malwareanalyzer.com/v1/reports/<sha256>` on
2026-09-26, for the **EICAR anti-malware test file**, whose SHA-256 is
`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`. EICAR is
published by EICAR for exactly this purpose, contains no code and no customer
data, and the service already held an analysis of it.

**No file was uploaded to obtain this.** It is the response to a GET by hash.
Bulky sections that the adapter does not map (`strings`, `featureVector`,
`entropyMap`, the 51-entry `engines` array, `packer`) were removed; every field
the adapter reads is present, byte for byte as returned.

It is kept because it carries three facts no invented payload would:
`visibility: "public"`, `tlp: "clear"`, and an empty `attack` array sitting
next to `behavior.analyzed: false`. That last pairing is the case the
`UNAVAILABLE` sentinel exists for, and a hand-written fixture would have got it
wrong by writing an empty list and meaning "none".

## Synthetic

`malwareanalyzer_submit_*.json`, `malwareanalyzer_poll_*.json`,
`capev2_*.json`

Hand-written, vendor-shaped, and **not recorded**. They exist because
recording them would have required submitting a file or a URL, and no file was
uploaded to a third party at any point in this work.

The MalwareAnalyzer submit and poll shapes follow a characterisation supplied
by the maintainer, who performed one URL submission of `https://example.com/`.
They are therefore second-hand and are labelled here so nobody later mistakes
them for a capture. The CAPEv2 payloads follow the documented CAPEv2 REST API
and have not been verified against a live instance.

No fixture here contains customer data, a credential, or a real malicious
sample.
