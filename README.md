# Hybrid-Detection-YARA



# Hybrid Detection YARA

A practical collection of YARA rules for detecting common threats across hybrid enterprise environments, including Windows, Linux, cloud workloads, web applications, and office documents.

## Purpose

This repository provides high-level, threat-informed YARA rules designed for SOC teams, detection engineers, malware analysts, and security operations architects.

The goal is not to provide perfect signatures, but reusable detection logic that can be tested, tuned, and adapted to real enterprise environments.

## Detection Scope

- Credential dumping
- PowerShell abuse
- Office macro droppers
- Ransomware indicators
- Webshell patterns
- Suspicious packed executables
- Linux and cloud reconnaissance
- AWS metadata abuse
- Common C2 artifacts

## Repository Structure

Rules are grouped by platform and adversary behavior.

## Example Rule

```yara
rule Suspicious_Credential_Dumping_Tool
{
    meta:
        description = "Detects common credential dumping strings"
        author = "Reza Adineh"
        severity = "critical"
        mitre_attack = "T1003"
        platform = "Windows"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "privilege::debug" nocase

    condition:
        any of them
}
    ├── mitre_attack_mapping.csv
    ├── platforms.csv
    └── data_sources.csv
