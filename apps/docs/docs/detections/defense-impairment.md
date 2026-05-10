---
sidebar_position: 4
---

# Defense Impairment Detection

Defense Impairment detection capabilities identify when adversaries attempt to disable or circumvent security tools and defenses to avoid detection. This is a critical detection category as it represents active evasion attempts by sophisticated attackers.

## Overview

Defense Impairment techniques (MITRE ATT&CK T1562) involve actions taken by adversaries to evade or disable security tools and defenses. These techniques are often employed early in an attack lifecycle to establish persistence and maintain access while avoiding detection.

## Detection Coverage

AiSOC provides comprehensive detection coverage for Defense Impairment techniques:

### T1562.001 - Disable or Modify Tools

Detects attempts to disable or terminate security tools such as antivirus, EDR, or monitoring agents.

**Sample Detection Rule:**
```yaml
id: det-endpoint-051
name: Prevent Defense Tool Execution
description: Adversaries may prevent the execution of security tools to avoid detection.
severity: high
category: endpoint
tags:
  - mitre.attack.T1562.001
  - tlp.white
log_source:
  product: windows
  service: sysmon
detection:
  condition: |
    parent_image IN ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
    AND image IN ["taskkill.exe", "net.exe", "net1.exe", "sc.exe", "wevtutil.exe", "fsutil.exe"]
    AND command_line CONTAINS_ANY ["Stop-Service", "Stop-Process", "taskkill", "net stop", "sc stop", "wevtutil cl", "fsutil behavior set DisableDeleteNotify 0"]
playbook: tpl-defense-evasion
```

### T1089 - Disabling Security Tools

Identifies attempts to disable firewall or network security tools.

### T1070 - Indicator Removal on Host

Detects actions to clear logs or remove forensic artifacts.

## Threat Actor Attribution

Our Threat Actor Attribution Engine has been enhanced to recognize Defense Impairment techniques as key indicators of sophisticated adversaries:

- **APT28 (Fancy Bear)**: Known to use defense evasion techniques to maintain persistence
- **APT29 (Cozy Bear)**: Employs advanced defense evasion to avoid detection
- **Lazarus Group**: Uses defense impairment to facilitate financial crimes

The attribution engine weights Defense Impairment techniques in the TTP scoring to improve accuracy when identifying these sophisticated threat actors.

## Playbook Integration

When Defense Impairment detections are triggered, the following automated response is initiated:

1. **System Isolation**: Immediately isolate the affected system to prevent further compromise
2. **Control Restoration**: Automatically restore disabled security controls
3. **Forensic Collection**: Gather evidence of the impairment attempt
4. **Investigation Initiation**: Create a case for deeper analysis
5. **Notification**: Alert security teams via Slack and email

## False Positives

Common legitimate activities that may trigger false positives:

- Scheduled maintenance scripts stopping services
- Legitimate administrative activities
- Automated patch management processes
- System shutdown/restart procedures

## Best Practices

1. **Monitor Privileged Accounts**: Pay special attention to Defense Impairment activities from privileged accounts
2. **Correlate Events**: Look for patterns of multiple defense tools being disabled in a short timeframe
3. **Baseline Normal Activity**: Understand normal service stop/start patterns in your environment
4. **Implement Multi-Layered Detection**: Combine endpoint, network, and cloud detection for comprehensive coverage

## Related Techniques

- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)

For more information on Defense Impairment techniques, visit the [MITRE ATT&CK T1562](https://attack.mitre.org/techniques/T1562/) page.