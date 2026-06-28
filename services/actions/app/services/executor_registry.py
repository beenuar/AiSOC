"""
Executor registry: maps ActionType to executor implementation.

WS-E live vendor integrations are wired here alongside the original simulation executors.
Each executor falls back to simulation mode when vendor credentials are absent from
ActionRequest.parameters — no credentials = safe, observable simulation.
"""

from app.executors.chatops import ChatOpsVerifyExecutor
from app.executors.endpoint import (
    IsolateHostExecutor,
    KillProcessExecutor,
    QuarantineFileExecutor,
    RunAVScanExecutor,
    RunScriptExecutor,
)
from app.executors.identity import (
    DisableUserExecutor,
    ForceMFAExecutor,
    ResetPasswordExecutor,
    SuspendSessionExecutor,
)
from app.executors.network import AllowIPExecutor, BlockDomainExecutor, BlockIPExecutor
from app.executors.notification import CreateTicketExecutor, NotifySlackExecutor
from app.executors.siem import (
    AckAlertExecutor,
    BlockIOCExecutor,
    CreateNotableEventExecutor,
    SearchSIEMExecutor,
    SuppressAlertExecutor,
    SyncDetectionRuleExecutor,
    UpdateWatcherExecutor,
)
from app.models.action import ActionType

EXECUTOR_REGISTRY = {
    # Network
    ActionType.BLOCK_IP: BlockIPExecutor(),
    ActionType.ALLOW_IP: AllowIPExecutor(),
    ActionType.BLOCK_DOMAIN: BlockDomainExecutor(),
    # Endpoint (CrowdStrike RTR + Microsoft Defender)
    ActionType.ISOLATE_HOST: IsolateHostExecutor(),
    ActionType.QUARANTINE_FILE: QuarantineFileExecutor(),
    ActionType.KILL_PROCESS: KillProcessExecutor(),
    ActionType.RUN_SCRIPT: RunScriptExecutor(),
    ActionType.RUN_AV_SCAN: RunAVScanExecutor(),
    # Identity (Okta)
    ActionType.DISABLE_USER: DisableUserExecutor(),
    ActionType.RESET_PASSWORD: ResetPasswordExecutor(),
    ActionType.SUSPEND_SESSION: SuspendSessionExecutor(),
    ActionType.FORCE_MFA: ForceMFAExecutor(),
    # SIEM (Splunk + Elastic) + Defender IoC
    ActionType.SEARCH_SIEM: SearchSIEMExecutor(),
    ActionType.CREATE_NOTABLE_EVENT: CreateNotableEventExecutor(),
    ActionType.SYNC_DETECTION_RULE: SyncDetectionRuleExecutor(),
    ActionType.UPDATE_WATCHER: UpdateWatcherExecutor(),
    ActionType.BLOCK_IOC: BlockIOCExecutor(),
    # Phase 3.3 — alert lifecycle (Splunk ES / Elastic Security / MDE).
    ActionType.ACK_ALERT: AckAlertExecutor(),
    ActionType.SUPPRESS_ALERT: SuppressAlertExecutor(),
    # Notifications & orchestration
    ActionType.NOTIFY_SLACK: NotifySlackExecutor(),
    ActionType.CREATE_TICKET: CreateTicketExecutor(),
    ActionType.CHATOPS_VERIFY: ChatOpsVerifyExecutor(),
}
