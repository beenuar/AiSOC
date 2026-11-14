package activity

import (
	"regexp"
	"strings"
)

// User-agent parsing, in Go, inside ingest.
//
// It belongs here rather than in a downstream service because the string is
// on the event at normalization time and every consumer wants the same
// answer. It is deliberately a *classifier* rather than a full UA database:
// the question a SOC asks of a user agent is not "which Chrome point release"
// but "was this a browser, a CLI, an SDK, an infrastructure-as-code tool, or
// something from an offensive toolkit", and a 50 MB regex corpus answers the
// first question at the cost of a dependency and a monthly update.
//
// The raw string is kept beside the parse on every event. A user agent is
// attacker-controlled, any parser is a lossy summary of it, and a hunt needs
// the original — a tool renamed to "Mozilla/5.0" is itself the finding.

// ClientCategory is what kind of thing sent the request.
type ClientCategory string

const (
	ClientBrowser   ClientCategory = "browser"
	ClientCLI       ClientCategory = "cli"
	ClientSDK       ClientCategory = "sdk"
	ClientIaC       ClientCategory = "iac"
	ClientOffensive ClientCategory = "offensive"
	// ClientInfrastructure is a monitoring agent, health checker or load
	// balancer — the traffic that is always there and almost never the
	// answer, which is worth labelling so it can be excluded on purpose.
	ClientInfrastructure ClientCategory = "infrastructure"
	ClientUnknown        ClientCategory = "unknown"
)

// Client is the parsed user agent plus the string it was parsed from.
type Client struct {
	Raw      string         `json:"raw,omitempty"`
	Family   string         `json:"family,omitempty"`
	Version  string         `json:"version,omitempty"`
	Category ClientCategory `json:"category,omitempty"`
}

// signature matches one client family. `pattern` is matched
// case-insensitively against the raw string; `version` optionally extracts
// the version that follows.
type signature struct {
	family   string
	category ClientCategory
	pattern  *regexp.Regexp
	version  *regexp.Regexp
}

func sig(family string, category ClientCategory, pattern, version string) signature {
	s := signature{family: family, category: category, pattern: regexp.MustCompile(`(?i)` + pattern)}
	if version != "" {
		s.version = regexp.MustCompile(`(?i)` + version)
	}
	return s
}

// signatures is ordered, most specific first, and the order is load-bearing
// rather than cosmetic in three places:
//
//   - every offensive tool is ahead of every browser and SDK, because
//     several of them send a browser-shaped string with their own name
//     appended and the browser pattern would otherwise swallow them;
//   - Edge is ahead of Chrome and Chrome ahead of Safari, because each of
//     those strings contains the next one;
//   - the generic HTTP libraries are last, because an SDK built on one still
//     names itself first.
var signatures = []signature{
	// ── offensive tooling ─────────────────────────────────────────────
	// Cloud and identity attack tools first: these are the ones that show
	// up in the sources this projection covers.
	sig("Pacu", ClientOffensive, `\bPacu\b`, ""),
	sig("ScoutSuite", ClientOffensive, `Scout\s?Suite`, ""),
	sig("CloudMapper", ClientOffensive, `CloudMapper`, ""),
	sig("Prowler", ClientOffensive, `\bProwler\b`, ""),
	sig("ROADtools", ClientOffensive, `ROADtools|roadrecon`, ""),
	sig("AADInternals", ClientOffensive, `AADInternals`, ""),
	sig("impacket", ClientOffensive, `impacket`, ""),
	sig("CobaltStrike", ClientOffensive, `Cobalt\s?Strike`, ""),
	sig("Metasploit", ClientOffensive, `Metasploit|Meterpreter`, ""),
	sig("sqlmap", ClientOffensive, `sqlmap`, `sqlmap/([\d.]+)`),
	sig("Nmap", ClientOffensive, `\bNmap\b|Nmap Scripting Engine`, ""),
	sig("Nuclei", ClientOffensive, `Nuclei`, ""),
	sig("Nikto", ClientOffensive, `Nikto`, ""),
	sig("gobuster", ClientOffensive, `gobuster`, ""),
	sig("ffuf", ClientOffensive, `\bffuf\b`, ""),
	sig("Hydra", ClientOffensive, `\bTHC-Hydra\b|\bhydra/`, ""),
	sig("Burp", ClientOffensive, `Burp\s?Suite|BurpCollaborator`, ""),
	sig("evil-winrm", ClientOffensive, `evil-winrm`, ""),

	// ── infrastructure-as-code ────────────────────────────────────────
	sig("Terraform", ClientIaC, `(?:HashiCorp/)?[Tt]erraform`, `[Tt]erraform/([\d.]+)`),
	sig("OpenTofu", ClientIaC, `OpenTofu`, `OpenTofu/([\d.]+)`),
	sig("Pulumi", ClientIaC, `[Pp]ulumi`, `pulumi/([\d.]+)`),
	sig("CloudFormation", ClientIaC, `cloudformation\.amazonaws\.com|CloudFormation`, ""),
	sig("Ansible", ClientIaC, `ansible-httpget|[Aa]nsible`, `[Aa]nsible/([\d.]+)`),
	sig("aws-cdk", ClientIaC, `aws-cdk`, `aws-cdk/([\d.]+)`),
	sig("Crossplane", ClientIaC, `[Cc]rossplane`, ""),

	// ── infrastructure and monitoring ─────────────────────────────────
	sig("ELB-HealthChecker", ClientInfrastructure, `ELB-HealthChecker`, ""),
	sig("kube-probe", ClientInfrastructure, `kube-probe`, `kube-probe/([\d.]+)`),
	sig("Prometheus", ClientInfrastructure, `Prometheus`, `Prometheus/([\d.]+)`),
	sig("Datadog-Agent", ClientInfrastructure, `Datadog(?:[ -]Agent)?`, ""),
	sig("Zabbix", ClientInfrastructure, `Zabbix`, ""),
	sig("GoogleHC", ClientInfrastructure, `GoogleHC`, ""),

	// ── command-line tools ────────────────────────────────────────────
	// aws-cli is ahead of Boto3: the CLI's own string contains `Botocore`.
	sig("aws-cli", ClientCLI, `aws-cli`, `aws-cli/([\d.]+)`),
	sig("gcloud", ClientCLI, `google-cloud-sdk|gcloud`, `(?:google-cloud-sdk|gcloud)/([\d.]+)`),
	sig("az-cli", ClientCLI, `AZURECLI`, `AZURECLI/([\d.]+)`),
	sig("kubectl", ClientCLI, `kubectl`, `kubectl/v?([\d.]+)`),
	sig("gh-cli", ClientCLI, `GitHub CLI`, `GitHub CLI ([\d.]+)`),
	sig("oci-cli", ClientCLI, `Oracle-PythonCLI`, ""),
	sig("curl", ClientCLI, `\bcurl/`, `curl/([\d.]+)`),
	sig("wget", ClientCLI, `\bWget/`, `Wget/([\d.]+)`),
	sig("HTTPie", ClientCLI, `HTTPie`, `HTTPie/([\d.]+)`),
	sig("PowerShell", ClientCLI, `WindowsPowerShell|PowerShell`, `PowerShell/([\d.]+)`),

	// ── vendor SDKs ───────────────────────────────────────────────────
	sig("Boto3", ClientSDK, `Boto3|Botocore`, `Boto3/([\d.]+)`),
	sig("aws-sdk-go", ClientSDK, `aws-sdk-go`, `aws-sdk-go/([\d.]+)`),
	sig("aws-sdk-java", ClientSDK, `aws-sdk-java`, `aws-sdk-java/([\d.]+)`),
	sig("aws-sdk-js", ClientSDK, `aws-sdk-js|aws-sdk-nodejs`, `aws-sdk-(?:js|nodejs)/([\d.]+)`),
	sig("google-api-client", ClientSDK, `google-api-(?:python|go|java|nodejs)-client`, ""),
	sig("Azure-SDK", ClientSDK, `azsdk-|Azure-SDK`, ""),
	sig("okta-sdk", ClientSDK, `okta-sdk`, ""),
	sig("Octokit", ClientSDK, `octokit`, `octokit[.\w]*/([\d.]+)`),

	// ── browsers ──────────────────────────────────────────────────────
	// Each of these strings contains the one after it, so the order here
	// is the whole correctness of the block.
	sig("Edge", ClientBrowser, `Edg[e]?/`, `Edg[e]?/([\d.]+)`),
	sig("Opera", ClientBrowser, `OPR/|Opera`, `(?:OPR|Opera)/([\d.]+)`),
	sig("Firefox", ClientBrowser, `Firefox/`, `Firefox/([\d.]+)`),
	sig("Chrome", ClientBrowser, `Chrome/|CriOS/`, `(?:Chrome|CriOS)/([\d.]+)`),
	sig("Safari", ClientBrowser, `Safari/`, `Version/([\d.]+)`),
	sig("IE", ClientBrowser, `MSIE |Trident/`, `(?:MSIE |rv:)([\d.]+)`),

	// ── generic HTTP libraries, last ──────────────────────────────────
	sig("python-requests", ClientSDK, `python-requests`, `python-requests/([\d.]+)`),
	sig("python-urllib", ClientSDK, `[Pp]ython-urllib`, `[Pp]ython-urllib/([\d.]+)`),
	sig("Go-http-client", ClientSDK, `Go-http-client`, `Go-http-client/([\d.]+)`),
	sig("okhttp", ClientSDK, `okhttp`, `okhttp/([\d.]+)`),
	sig("axios", ClientSDK, `axios`, `axios/([\d.]+)`),
	sig("Java", ClientSDK, `^Java/`, `Java/([\d.]+)`),
	sig("libcurl", ClientSDK, `libcurl`, `libcurl/([\d.]+)`),
}

// ParseUserAgent classifies a raw user-agent string.
//
// An empty string returns an empty Client rather than one labelled unknown:
// "no user agent was sent" and "a user agent was sent that we could not
// place" are different facts, and a source with no UA field at all should
// not acquire a client block.
func ParseUserAgent(raw string) Client {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Client{}
	}
	// Bound what a single attacker-chosen header can cost. The longest
	// legitimate agent seen in these sources is well under this.
	const maxLen = 512
	if len(raw) > maxLen {
		raw = raw[:maxLen]
	}

	for _, s := range signatures {
		if !s.pattern.MatchString(raw) {
			continue
		}
		client := Client{Raw: raw, Family: s.family, Category: s.category}
		if s.version != nil {
			if m := s.version.FindStringSubmatch(raw); len(m) > 1 {
				client.Version = m[1]
			}
		}
		return client
	}
	return Client{Raw: raw, Category: ClientUnknown}
}
