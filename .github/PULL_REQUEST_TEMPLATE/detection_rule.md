## Detection rule contribution

<!-- Use this template when submitting new detection rules or translations.
     For bug fixes / features, use the default PR template instead. -->

### Rule metadata

| Field             | Value |
|-------------------|-------|
| **Rule file(s)**  | `detections/<category>/<filename>.yaml` |
| **Category**      | <!-- cloud / endpoint / identity / network / application --> |
| **Severity**      | <!-- critical / high / medium / low --> |
| **MITRE ATT&CK**  | <!-- e.g. T1078.004, T1098.001 --> |
| **Log source**    | <!-- e.g. aws/cloudtrail, windows/sysmon, azure/signin --> |

### Type of contribution

- [ ] New detection rule (original Sigma / AiSOC-native YAML)
- [ ] Translation of existing rule to a new platform (SPL / KQL / ES|QL / YARA-L2)
- [ ] Improvement to existing rule (tuning, FP reduction, new conditions)
- [ ] Detection rule fix (broken logic, wrong severity, incorrect MITRE mapping)

### Description

<!-- Describe what this detection catches and why it matters.
     Include the attack scenario and any references (blog posts, CVEs, etc). -->

### Detection logic

<!-- Briefly explain the logic: what event source, what conditions, and what
     distinguishes true positives from false positives. -->

### False positives

<!-- List known FP scenarios so operators can tune appropriately. -->

- 

### Testing

- [ ] Rule validates with `python3 scripts/validate_detections.py`
- [ ] Tested against sample log data (describe below)
- [ ] False-positive scenarios documented above

<details>
<summary>Test evidence</summary>

<!-- Paste sample events, screenshots, or test output showing the rule fires
     on true-positive data and does not fire on benign data. -->

</details>

### Checklist

- [ ] Rule YAML follows the schema in `detections/` (id, name, description, version, severity, tags, category, log_source, detection, false_positives, playbook, enabled, author, created, modified)
- [ ] `id` uses the next available `det-<category>-NNN` sequence number
- [ ] MITRE ATT&CK tags use lowercase dotted notation (`mitre.attack.tNNNN.NNN`)
- [ ] `severity` is one of: `critical`, `high`, `medium`, `low`
- [ ] `category` matches the parent directory name
- [ ] No secrets, API keys, or PII in the rule file
- [ ] I have read the [Contributing Guide](https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md)

### References

<!-- Links to threat research, vendor docs, or CVEs that informed this rule. -->

- 
