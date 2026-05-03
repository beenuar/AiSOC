// Package aisoc provides a typed Go client for the AiSOC REST API.
package aisoc

import "time"

// AlertSeverity is the severity level of a security alert.
type AlertSeverity string

const (
	AlertSeverityCritical AlertSeverity = "critical"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityInfo     AlertSeverity = "info"
)

// AlertStatus is the triage state of an alert.
type AlertStatus string

const (
	AlertStatusOpen         AlertStatus = "open"
	AlertStatusInProgress   AlertStatus = "in_progress"
	AlertStatusClosed       AlertStatus = "closed"
	AlertStatusFalsePositive AlertStatus = "false_positive"
)

// CasePriority is the urgency of a case.
type CasePriority string

const (
	CasePriorityCritical CasePriority = "critical"
	CasePriorityHigh     CasePriority = "high"
	CasePriorityMedium   CasePriority = "medium"
	CasePriorityLow      CasePriority = "low"
)

// CaseStatus is the lifecycle state of a case.
type CaseStatus string

const (
	CaseStatusOpen          CaseStatus = "open"
	CaseStatusInvestigating CaseStatus = "investigating"
	CaseStatusResolved      CaseStatus = "resolved"
	CaseStatusClosed        CaseStatus = "closed"
)

// Alert represents a security event raised by a detection rule or connector.
type Alert struct {
	ID           string        `json:"id"`
	TenantID     string        `json:"tenant_id"`
	Title        string        `json:"title"`
	Severity     AlertSeverity `json:"severity"`
	Status       AlertStatus   `json:"status"`
	Source       string        `json:"source"`
	SourceRef    *string       `json:"source_ref,omitempty"`
	MitreTactics []string      `json:"mitre_tactics"`
	AIScore      *float64      `json:"ai_score,omitempty"`
	CaseID       *string       `json:"case_id,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// Case represents an investigated security incident.
type Case struct {
	ID           string       `json:"id"`
	TenantID     string       `json:"tenant_id"`
	CaseNumber   string       `json:"case_number"`
	Title        string       `json:"title"`
	Status       CaseStatus   `json:"status"`
	Priority     CasePriority `json:"priority"`
	Assignee     *string      `json:"assignee,omitempty"`
	MitreTactics []string     `json:"mitre_tactics"`
	AlertIDs     []string     `json:"alert_ids"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// DetectionRule represents a SIEM or EDR detection rule.
type DetectionRule struct {
	ID           string        `json:"id"`
	TenantID     string        `json:"tenant_id"`
	Name         string        `json:"name"`
	Description  *string       `json:"description,omitempty"`
	RuleLanguage string        `json:"rule_language"`
	Severity     AlertSeverity `json:"severity"`
	Enabled      bool          `json:"enabled"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// Connector represents an integration source.
type Connector struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	ConnectorType  string    `json:"connector_type"`
	IsEnabled      bool      `json:"is_enabled"`
	HealthStatus   string    `json:"health_status"`
	EventsIngested int64     `json:"events_ingested"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PlaybookStep is a single action node in an automation playbook.
type PlaybookStep struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Action     *string                `json:"action,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	NextSteps  []string               `json:"next_steps"`
}

// Playbook is an automation workflow.
type Playbook struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       *string                `json:"description,omitempty"`
	Version           string                 `json:"version"`
	Steps             []PlaybookStep         `json:"steps"`
	TriggerConditions map[string]interface{} `json:"trigger_conditions,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// PlaybookRun tracks an in-progress or completed playbook execution.
type PlaybookRun struct {
	RunID       string                 `json:"run_id"`
	PlaybookID  string                 `json:"playbook_id"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	TriggerData map[string]interface{} `json:"trigger_data,omitempty"`
	StepResults map[string]interface{} `json:"step_results,omitempty"`
}

// APIKey is a scoped machine credential.
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Page is a generic paginated response envelope.
type Page[T any] struct {
	Items    []T `json:"items"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// APIKeyCreateRequest is the body for creating a scoped API key.
type APIKeyCreateRequest struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// APIKeyCreateResponse is returned on successful key creation.
type APIKeyCreateResponse struct {
	Key    APIKey `json:"key"`
	RawKey string `json:"raw_key"` // Only returned once — store securely.
}

// AlertFilters are optional query parameters for listing alerts.
type AlertFilters struct {
	Severity *AlertSeverity
	Status   *AlertStatus
	CaseID   *string
	Search   *string
	Page     int
	PageSize int
}

// CaseFilters are optional query parameters for listing cases.
type CaseFilters struct {
	Status   *CaseStatus
	Priority *CasePriority
	Assignee *string
	Page     int
	PageSize int
}
