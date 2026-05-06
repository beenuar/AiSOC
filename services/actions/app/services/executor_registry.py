"""
Executor registry: maps ActionType to executor implementation.
"""

from app.executors.chatops import ChatOpsVerifyExecutor
from app.executors.endpoint import IsolateHostExecutor, KillProcessExecutor, QuarantineFileExecutor
from app.executors.network import BlockDomainExecutor, BlockIPExecutor
from app.executors.notification import CreateTicketExecutor, NotifySlackExecutor
from app.models.action import ActionType

EXECUTOR_REGISTRY = {
    ActionType.BLOCK_IP: BlockIPExecutor(),
    ActionType.BLOCK_DOMAIN: BlockDomainExecutor(),
    ActionType.ISOLATE_HOST: IsolateHostExecutor(),
    ActionType.QUARANTINE_FILE: QuarantineFileExecutor(),
    ActionType.KILL_PROCESS: KillProcessExecutor(),
    ActionType.NOTIFY_SLACK: NotifySlackExecutor(),
    ActionType.CREATE_TICKET: CreateTicketExecutor(),
    ActionType.CHATOPS_VERIFY: ChatOpsVerifyExecutor(),
}
