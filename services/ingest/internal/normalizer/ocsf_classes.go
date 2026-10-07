package normalizer

// OCSF event classes, and which one each connector type's telemetry is.
//
// Every uid, caption and category below was read from the published schema
// before it was used here, not recalled:
//
//	https://schema.ocsf.io/api/1.9.0/classes   (the version the tree targets)
//	https://schema.ocsf.io/api/1.1.0/classes   (the version metadata.version declares)
//
// Both were checked because the two numbers are not the same thing. The
// normalizer stamps `metadata.version: 1.1.0` as its contract with
// connectors, while the evidence bundle declares 1.9.0
// (`docs/architecture/evidence-bundles.md`), and emitting a class that exists
// only in the newer schema under the older version string would be a false
// claim about a public standard. Every class named here carries the same uid,
// caption and category in both, so the question does not arise — but it was
// asked, and it is why this file lists two URLs rather than one.
//
// Why a connector's class is load-bearing rather than cosmetic
// ------------------------------------------------------------
// `should_promote()` in services/fusion/app/services/promoter.py promotes an
// event to an alert when it is OCSF category 2 (Findings) **or** its
// severity_id is at least 4. The category is the class uid divided by a
// thousand, so the class a connector's events carry decides whether its
// routine telemetry reaches an analyst's queue or stays in the lake.
//
// Before this table, every connector without a hand-written profile landed on
// 2001 Security Finding through `canonicalProfile` — category 2, therefore
// always promoted. For the connectors whose fetch_alerts really does return
// vendor findings that is right. For the ones returning raw telemetry it
// meant every permitted DNS lookup, every allowed proxy request, every
// accepted VPC flow record and every routine Windows event became an alert
// carrying severity "info": the alert-reduction property fusion exists to
// provide, inverted, for the sources that emit the most volume.
//
// The split mirrors the one `ai_runtime` and `ai_guardrail` already make in
// normalizer.go, for the same stated reason: routine activity at a category
// the promoter leaves alone, judged findings at category 2.
//
// How a connector's class was chosen
// ----------------------------------
// By what its `fetch_alerts` actually returns, read from the connector rather
// than inferred from the vendor's product category — the two disagree often
// enough that guessing would have demoted four sources that only ever return
// findings. Netskope's connector reads `/api/v2/events/data/alert` and
// Proofpoint's reads `/v2/siem/messages/blocked`, so both return judgements
// and keep category 2; Zscaler's reads web logs with `action: "any"` and
// Cisco Umbrella's reads `/activity`, so both are telemetry and take their
// activity class. Where a stream is genuinely mixed the class covering the
// security-relevant majority is used and the entry says so.

// OCSF class uids this service may emit. Named rather than spelled inline so
// the gate reads one table and a reader can see the category each implies
// (uid/1000), which is what decides promotion.
const (
	// Category 1 — System Activity.
	classFileSystemActivity = 1001
	classProcessActivity    = 1007

	// Category 2 — Findings. Promoted unconditionally.
	classSecurityFinding      = 2001
	classVulnerabilityFinding = 2002

	// Category 3 — Identity & Access Management.
	classAccountChange        = 3001
	classAuthentication       = 3002
	classUserAccessManagement = 3005
	classGroupManagement      = 3006

	// Category 4 — Network Activity.
	classNetworkActivity  = 4001
	classHTTPActivity     = 4002
	classDNSActivity      = 4003
	classEmailActivity    = 4009
	classEmailURLActivity = 4012

	// Category 6 — Application Activity.
	classWebResourcesActivity = 6001
	classAPIActivity          = 6003
	classDatastoreActivity    = 6005
	classFileHostingActivity  = 6006
)

// ocsfClass is one row of the published schema, carried here so the mapping
// below names a class rather than an integer and so a wrong caption cannot
// ship: the Go test asserts uid/1000 equals the declared category for every
// row and pins every caption against the schema.
type ocsfClass struct {
	uid      int
	caption  string
	category int
}

// ocsfClasses is the closed set. A mapping or a webhook template naming a uid
// absent from here fails the Go test and the gate, which is what stops an
// invented class uid from reaching the lake.
var ocsfClasses = map[int]ocsfClass{
	classFileSystemActivity:   {classFileSystemActivity, "File System Activity", 1},
	classProcessActivity:      {classProcessActivity, "Process Activity", 1},
	classSecurityFinding:      {classSecurityFinding, "Security Finding", 2},
	classVulnerabilityFinding: {classVulnerabilityFinding, "Vulnerability Finding", 2},
	classAccountChange:        {classAccountChange, "Account Change", 3},
	classAuthentication:       {classAuthentication, "Authentication", 3},
	classUserAccessManagement: {classUserAccessManagement, "User Access Management", 3},
	classGroupManagement:      {classGroupManagement, "Group Management", 3},
	classNetworkActivity:      {classNetworkActivity, "Network Activity", 4},
	classHTTPActivity:         {classHTTPActivity, "HTTP Activity", 4},
	classDNSActivity:          {classDNSActivity, "DNS Activity", 4},
	classEmailActivity:        {classEmailActivity, "Email Activity", 4},
	classEmailURLActivity:     {classEmailURLActivity, "Email URL Activity", 4},
	classWebResourcesActivity: {classWebResourcesActivity, "Web Resources Activity", 6},
	classAPIActivity:          {classAPIActivity, "API Activity", 6},
	classDatastoreActivity:    {classDatastoreActivity, "Datastore Activity", 6},
	classFileHostingActivity:  {classFileHostingActivity, "File Hosting Activity", 6},
}

// classesWithNoProducerYet records a declared class that nothing in the tree
// emits, and why it is declared ahead of its producer.
//
// All three are *per-event* classes inside streams this table can only
// describe per connector: a file syscall inside auditd's stream, a privilege
// grant inside an IdP's sign-in stream, a group membership change inside a
// directory's account stream. Choosing one of them as a whole connector's
// class would misdescribe the majority of that connector's records, which is
// the opposite of what this table is for. The event catalogue (depth plan
// 2.3) is the per-event discriminator that reaches them.
//
// Declaring them anyway is deliberate: they are the vocabulary the catalogue
// will map onto, verified against the schema now rather than invented later.
// `TestEveryDeclaredClassIsReachableOrRecorded` requires every declared class
// to be reached or listed here, and requires a listed class that *has*
// acquired a producer to be removed — so the list can only shrink.
var classesWithNoProducerYet = map[int]string{
	classFileSystemActivity: "a file syscall inside auditd's and osquery's streams, whose majority shape is process activity",
	classUserAccessManagement: "a privilege grant inside an IdP's stream, whose majority shape is authentication; " +
		"Vault's audit log is the nearest whole-connector fit and is a secrets datastore, not a privilege manager",
	classGroupManagement: "a group membership change inside a directory's stream, whose majority shape is account change",
}

// connectorClass is the decision recorded for one connector type: either the
// OCSF class its canonical events carry, or the reason it is left on the
// Security Finding default.
//
// `genericReason` is not an escape hatch for "nobody looked" — it is the
// opposite. A connector reaching the default silently is the state this table
// exists to end; one reaching it with a sentence saying why is a decision
// somebody can disagree with in review.
type connectorClass struct {
	classUID      int
	genericReason string
}

// connectorOCSFClass carries a decision for every connector type
// services/connectors declares. Exactly one field per entry: the gate
// (`scripts/check_ocsf_class_coverage.py`) fails on a declared connector with
// neither, and on an entry carrying both.
var connectorOCSFClass = map[string]connectorClass{
	// ---------------------------------------------------------------
	// Category 3 — identity. Sign-ins and directory changes.
	// ---------------------------------------------------------------
	"okta":         {classUID: classAuthentication},
	"azure_entra":  {classUID: classAuthentication},
	"auth0":        {classUID: classAuthentication},
	"duo_security": {classUID: classAuthentication},
	"onepassword":  {classUID: classAuthentication},
	// JumpCloud's directory insights are account lifecycle first and
	// authentication second: its event_type vocabulary is dominated by user
	// and group create, update and delete, with `success` carrying the auth
	// outcome. Account Change is the superset those records fit.
	"jumpcloud": {classUID: classAccountChange},

	// ---------------------------------------------------------------
	// Category 4 — network and email telemetry. High volume, mostly benign.
	// ---------------------------------------------------------------
	// Umbrella reads /activity: one record per DNS or proxy transaction,
	// with `verdict` carrying the decision. At 2001 every permitted lookup
	// in the estate became an alert.
	"cisco_umbrella": {classUID: classDNSActivity},
	// Secure web gateway and WAF logs: one record per web request, with the
	// policy action in the record. Zscaler's connector asks for
	// `action: "any"`, so an Allow arrives alongside a Quarantine.
	"zscaler": {classUID: classHTTPActivity},
	"imperva": {classUID: classHTTPActivity},
	// Cloudflare Zero Trust ships two modes from one connector — WAF
	// firewall events and Access application-request decisions. Both are a
	// decision taken on an HTTP request reaching an application.
	"cloudflare_zt": {classUID: classHTTPActivity},
	// Flow records and network-monitoring telemetry.
	"aws_vpc_flow":  {classUID: classNetworkActivity},
	"zeek_suricata": {classUID: classNetworkActivity},
	// Sublime reads /v1/messages, which is every message rather than only
	// the flagged ones, and defaults an unrecognised verdict to info.
	"sublime_security": {classUID: classEmailActivity},
	// Mimecast reads the TTP URL Protect log, which is one record per URL
	// click with a verdict — not a message stream, which is why it carries
	// the narrower class.
	"mimecast": {classUID: classEmailURLActivity},

	// ---------------------------------------------------------------
	// Category 1 — endpoint telemetry. The EDR products that return the
	// vendor's own detections are findings and are listed further down.
	// ---------------------------------------------------------------
	// auditd and the Windows Security channel are syscall and event-log
	// streams. Process creation is the dominant shape in both and the one
	// the detection corpus reads; their file-operation records are the
	// reason classFileSystemActivity is declared and not yet reached.
	"auditd":        {classUID: classProcessActivity},
	"windows_event": {classUID: classProcessActivity},
	// osquery results through FleetDM and osctrl are scheduled-query
	// differentials spanning processes, files, packages and host state. The
	// security-relevant majority is process and file telemetry; the
	// promotion consequence is right for the whole stream either way,
	// because a routine inventory row should not be an alert.
	"fleetdm": {classUID: classProcessActivity},
	"osctrl":  {classUID: classProcessActivity},

	// ---------------------------------------------------------------
	// Category 6 — application and data activity.
	// ---------------------------------------------------------------
	// Cloud control-plane audit logs: one API call per record.
	"gcp_cloud_audit":  {classUID: classAPIActivity},
	"azure_activity":   {classUID: classAPIActivity},
	"oci":              {classUID: classAPIActivity},
	"kubernetes_audit": {classUID: classAPIActivity},
	// Cloudflare's connector reads /accounts/{id}/audit_logs — the account
	// control plane, not the HTTP request logs its vendor is better known
	// for. Reading the connector rather than the brand is what keeps this
	// out of HTTP Activity.
	"cloudflare": {classUID: classAPIActivity},
	// Tailscale's connector reads /tailnet/{t}/audit: ACL and device
	// administration, not packets.
	"tailscale": {classUID: classAPIActivity},
	// SaaS audit trails. Workspace and M365 carry sign-in, admin, file and
	// mail events in one stream; API Activity holds the whole stream
	// honestly rather than claiming a precision the per-event discriminator
	// does not yet exist for.
	"google_workspace": {classUID: classAPIActivity},
	"m365_audit":       {classUID: classAPIActivity},
	"slack_audit":      {classUID: classAPIActivity},
	"salesforce":       {classUID: classAPIActivity},
	"servicenow":       {classUID: classAPIActivity},
	"jira":             {classUID: classAPIActivity},
	"confluence_audit": {classUID: classAPIActivity},
	// Source-control audit logs.
	"github": {classUID: classAPIActivity},
	"gitlab": {classUID: classAPIActivity},
	// Provider admin audit logs: who created a key, who changed a seat.
	"llm_usage": {classUID: classAPIActivity},
	// The schema's own description of File Hosting Activity names Box and
	// the services Dropbox competes with, which is why these two are not at
	// File System Activity: that class is a process acting on a local file.
	"box":     {classUID: classFileHostingActivity},
	"dropbox": {classUID: classFileHostingActivity},
	// Warehouse query and login history.
	"snowflake": {classUID: classDatastoreActivity},
	// Vault's audit records are an operation against a secret path — a
	// read, write or delete on a datastore — not a privilege update, which
	// is what User Access Management describes.
	"vault": {classUID: classDatastoreActivity},
	// The AI gateway's runtime log is a request per model or tool call
	// against a served resource.
	"ai_gateway": {classUID: classWebResourcesActivity},

	// ---------------------------------------------------------------
	// Vulnerability findings — category 2, so still promoted
	// unconditionally, but a class the lake can tell apart from a
	// detection.
	// ---------------------------------------------------------------
	"qualys":     {classUID: classVulnerabilityFinding},
	"tenable_io": {classUID: classVulnerabilityFinding},
	"snyk":       {classUID: classVulnerabilityFinding},

	// ---------------------------------------------------------------
	// Deliberately 2001 Security Finding. Each returns the vendor's own
	// judged findings, so category 2 and unconditional promotion is the
	// correct outcome rather than an oversight. The reason is recorded so a
	// reader can tell these apart from a connector nobody classified.
	// ---------------------------------------------------------------
	"crowdstrike":      {genericReason: "EDR detections: already judged by the vendor"},
	"sentinelone":      {genericReason: "EDR threats: already judged by the vendor"},
	"carbon_black":     {genericReason: "EDR alerts: already judged by the vendor"},
	"cortex_xdr":       {genericReason: "XDR incidents: already judged by the vendor"},
	"trend_vision_one": {genericReason: "XDR workbench alerts: already judged by the vendor"},
	"azure_defender":   {genericReason: "Defender alerts: already judged by the vendor"},
	"aws_guardduty":    {genericReason: "GuardDuty findings: already judged by the vendor"},
	"aws_security_hub": {genericReason: "Security Hub findings: already judged by the vendor"},
	"gcp_scc":          {genericReason: "Security Command Center findings: already judged by the vendor"},
	"wiz":              {genericReason: "cloud security issues: already judged by the vendor"},
	"orca":             {genericReason: "cloud security alerts: already judged by the vendor"},
	"lacework":         {genericReason: "cloud security events: already judged by the vendor"},
	"prisma_cloud":     {genericReason: "cloud security alerts: already judged by the vendor"},
	"sysdig":           {genericReason: "runtime security events: already judged by the vendor"},
	"darktrace":        {genericReason: "NDR model breaches: already judged by the vendor"},
	"greynoise":        {genericReason: "threat-intel verdicts on an address already observed"},
	"wazuh":            {genericReason: "agent alerts above a rule-level threshold: judged by the vendor's ruleset"},
	// Falco's connector drops anything below the configured priority, so
	// what reaches ingest is a rule hit the operator asked to see.
	"falco": {genericReason: "rule hits above a configured priority: the rule is the judgement"},
	// Netskope's connector reads /api/v2/events/data/alert, not the web
	// traffic log, so what arrives is already an alert.
	"netskope": {genericReason: "CASB alerts, not the web traffic log: already judged by the vendor"},
	// Proofpoint's connector reads /v2/siem/messages/blocked and Abnormal's
	// reads /v1/threats and /v1/cases — the judged half of each product.
	"proofpoint":        {genericReason: "messages the gateway blocked: already judged by the vendor"},
	"abnormal_security": {genericReason: "threats and cases, not the message stream: already judged by the vendor"},
	// A forwarded or reported message carries a human's judgement, which is
	// the whole reason it was forwarded.
	"email_inbox": {genericReason: "messages a person reported as suspicious: the report is the judgement"},
	// The connector ships a curated allow-list of security-relevant API
	// calls, so the selection has already happened upstream of ingest.
	"aws_cloudtrail": {genericReason: "a curated allow-list of security-relevant API calls: the connector has already decided"},
	"opsgenie":       {genericReason: "alerts raised by another system and forwarded"},
	"pagerduty":      {genericReason: "incidents raised by another system and forwarded"},
	"tines":          {genericReason: "SOAR story results: already judged by the sending workflow"},
	"torq":           {genericReason: "SOAR workflow results: already judged by the sending workflow"},
	// CEF and LEEF carry the sending device's own class and severity. One
	// class for every CEF sender would be a claim about devices this
	// connector cannot see.
	"syslog_cef": {genericReason: "CEF and LEEF carry the sending device's own class, which this connector cannot narrow"},

	// SIEMs forward notables and correlation-rule hits, which are findings
	// by construction: the search that produced them is the judgement.
	"splunk":             {genericReason: "SIEM notables: the correlation search is the judgement"},
	"microsoft_sentinel": {genericReason: "SIEM incidents: the analytics rule is the judgement"},
	"qradar":             {genericReason: "SIEM offenses: the rule chain is the judgement"},
	"elastic":            {genericReason: "SIEM detection alerts: the rule is the judgement"},
	"chronicle":          {genericReason: "SIEM detections: the rule is the judgement"},
	"cortex_xsiam":       {genericReason: "SIEM incidents: the correlation is the judgement"},
	"exabeam":            {genericReason: "SIEM notable sessions: the model is the judgement"},
	"securonix":          {genericReason: "SIEM violations: the policy is the judgement"},
	"devo":               {genericReason: "SIEM alerts: the rule is the judgement"},
	"sumo_logic":         {genericReason: "SIEM signals: the rule is the judgement"},
	"rapid7_insightidr":  {genericReason: "SIEM investigations: the detection rule is the judgement"},
	"trellix_helix":      {genericReason: "SIEM alerts: the rule is the judgement"},
	"datadog":            {genericReason: "monitor alerts: the monitor is the judgement"},
	"datadog_cloud_siem": {genericReason: "Cloud SIEM signals: the rule is the judgement"},
}

// ocsfClassForConnector returns the class a connector type's canonical events
// carry, and whether the table names one. A connector with a recorded
// `genericReason`, or no entry at all, returns false and keeps the default.
func ocsfClassForConnector(connectorType string) (ocsfClass, bool) {
	entry, ok := connectorOCSFClass[connectorType]
	if !ok || entry.classUID == 0 {
		return ocsfClass{}, false
	}
	class, known := ocsfClasses[entry.classUID]
	return class, known
}
