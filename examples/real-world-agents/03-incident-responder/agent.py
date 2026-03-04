"""
Incident Responder Agent
========================
Triggered by PagerDuty webhook. Automatically:
  1. Pulls alert details from PagerDuty
  2. Searches Datadog logs for the error pattern
  3. Checks Kubernetes pod status and recent events
  4. Attempts automated remediation (restart pod, scale up)
  5. Posts status updates to Slack incident channel

This is a multi-step agent with tool chaining — the output of one
MCP tool feeds into the next. Shows the cross-server escalation
pattern that MG003 detects.
"""

import asyncio
import json
from dataclasses import dataclass
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from anthropic import Anthropic


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    service: str
    triggered_at: str


# ── MCP Server Connections ──────────────────────────────────────────

SERVERS = {
    "pagerduty": StdioServerParameters(
        command="npx",
        args=["-y", "@acme/mcp-pagerduty"],
        env={"PAGERDUTY_API_KEY": "${PD_API_KEY}"},
    ),
    "datadog": StdioServerParameters(
        command="npx",
        args=["-y", "@acme/mcp-datadog"],
        env={
            "DD_API_KEY": "${DD_API_KEY}",
            "DD_APP_KEY": "${DD_APP_KEY}",
        },
    ),
    "kubernetes": StdioServerParameters(
        command="npx",
        args=["-y", "@acme/mcp-kubernetes"],
        env={
            "KUBECONFIG": "/home/oncall/.kube/config",
            # ← BUG: production k8s credentials on disk, no RBAC scoping
        },
    ),
    "slack": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-slack"],
        env={
            "SLACK_BOT_TOKEN": "xoxb-EXAMPLE-TOKEN-DO-NOT-USE",
            "SLACK_TEAM_ID": "T0000000001",
        },
    ),
    "shell": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-shell"],
        # ← BUG: unrestricted shell on the oncall machine
    ),
}

client = Anthropic()


# ── Step 1: Triage ─────────────────────────────────────────────────

async def triage_incident(
    pd_session: ClientSession,
    dd_session: ClientSession,
    incident_id: str,
) -> tuple[Incident, list[dict]]:
    """Pull alert details and find matching log entries."""

    # Get incident details from PagerDuty
    result = await pd_session.call_tool(
        "get_incident",
        arguments={"incident_id": incident_id},
    )
    incident_data = json.loads(result.content[0].text)
    incident = Incident(
        id=incident_data["id"],
        title=incident_data["title"],
        severity=incident_data["urgency"],
        service=incident_data["service"]["name"],
        triggered_at=incident_data["created_at"],
    )

    # Search Datadog logs for related errors
    log_result = await dd_session.call_tool(
        "search_logs",
        arguments={
            # ← BUG: unbounded query string, agent can search anything
            "query": f"service:{incident.service} status:error",
            "time_range": "15m",
            "limit": 50,
        },
    )
    logs = json.loads(log_result.content[0].text)

    return incident, logs


# ── Step 2: Diagnose ──────────────────────────────────────────────

async def diagnose(
    k8s_session: ClientSession,
    incident: Incident,
    logs: list[dict],
) -> dict:
    """Check pod status and determine root cause using Claude."""

    # Get pod status for the affected service
    pods_result = await k8s_session.call_tool(
        "get_pods",
        arguments={
            "namespace": "production",
            "label_selector": f"app={incident.service}",
        },
    )
    pods = json.loads(pods_result.content[0].text)

    # Get recent k8s events
    events_result = await k8s_session.call_tool(
        "get_events",
        arguments={
            "namespace": "production",
            "field_selector": f"involvedObject.name={incident.service}",
        },
    )
    events = json.loads(events_result.content[0].text)

    # Use Claude to diagnose
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        system="""You are an SRE diagnosing a production incident.
Given the alert, logs, pod status, and k8s events, determine:
1. Root cause (OOMKilled, CrashLoopBackOff, connection timeout, etc.)
2. Affected scope (single pod, all replicas, dependent services)
3. Recommended action (restart, scale up, rollback, escalate to human)

Return JSON: {"root_cause": "...", "scope": "...", "action": "...", "confidence": 0.0-1.0}""",
        messages=[{
            "role": "user",
            "content": json.dumps({
                "incident": incident.__dict__,
                "logs_sample": logs[:10],
                "pods": pods,
                "events": events,
            }),
        }],
    )

    return json.loads(response.content[0].text)


# ── Step 3: Remediate ─────────────────────────────────────────────

async def remediate(
    k8s_session: ClientSession,
    shell_session: ClientSession,
    incident: Incident,
    diagnosis: dict,
):
    """Execute automated remediation based on diagnosis."""

    action = diagnosis["action"]

    if action == "restart" and diagnosis["confidence"] > 0.8:
        # Rolling restart of the deployment
        await k8s_session.call_tool(
            "rollout_restart",
            arguments={
                "namespace": "production",
                "deployment": incident.service,
            },
        )
    elif action == "scale_up":
        await k8s_session.call_tool(
            "scale_deployment",
            arguments={
                "namespace": "production",
                "deployment": incident.service,
                "replicas": 5,
            },
        )
    elif action == "rollback":
        # ← DANGER: this shells out to kubectl with the service name
        # An attacker who controls the PagerDuty alert title could inject commands
        await shell_session.call_tool(
            "run_command",
            arguments={
                "command": f"kubectl rollout undo deployment/{incident.service} -n production",
            },
        )
    else:
        # Unknown action — do nothing, escalate to human
        pass


# ── Step 4: Status Update ────────────────────────────────────────

async def post_status(
    slack_session: ClientSession,
    incident: Incident,
    diagnosis: dict,
    remediation_done: bool,
):
    """Post incident status to the Slack incident channel."""

    status_emoji = "🟢" if remediation_done else "🔴"
    message = (
        f"{status_emoji} *Incident {incident.id}: {incident.title}*\n"
        f"• Service: `{incident.service}`\n"
        f"• Root cause: {diagnosis['root_cause']}\n"
        f"• Scope: {diagnosis['scope']}\n"
        f"• Action taken: {diagnosis['action']}\n"
        f"• Confidence: {diagnosis['confidence']:.0%}\n"
        f"• Auto-remediated: {'Yes' if remediation_done else 'No — needs human'}"
    )

    await slack_session.call_tool(
        "send_message",
        arguments={
            "channel": "#incidents",
            "text": message,
        },
    )


# ── Orchestrator ──────────────────────────────────────────────────

async def handle_incident(incident_id: str):
    """Full incident response pipeline."""

    async with (
        stdio_client(SERVERS["pagerduty"]) as (pd_r, pd_w),
        stdio_client(SERVERS["datadog"]) as (dd_r, dd_w),
        stdio_client(SERVERS["kubernetes"]) as (k8s_r, k8s_w),
        stdio_client(SERVERS["slack"]) as (sl_r, sl_w),
        stdio_client(SERVERS["shell"]) as (sh_r, sh_w),
    ):
        pd = ClientSession(pd_r, pd_w)
        dd = ClientSession(dd_r, dd_w)
        k8s = ClientSession(k8s_r, k8s_w)
        sl = ClientSession(sl_r, sl_w)
        sh = ClientSession(sh_r, sh_w)

        for s in [pd, dd, k8s, sl, sh]:
            await s.initialize()

        # Step 1: Triage
        print("🔍 Triaging incident...")
        incident, logs = await triage_incident(pd, dd, incident_id)
        print(f"  Alert: {incident.title} (severity: {incident.severity})")
        print(f"  Found {len(logs)} matching log entries")

        # Step 2: Diagnose
        print("🧠 Diagnosing root cause...")
        diagnosis = await diagnose(k8s, incident, logs)
        print(f"  Root cause: {diagnosis['root_cause']}")
        print(f"  Recommended: {diagnosis['action']} (confidence: {diagnosis['confidence']:.0%})")

        # Step 3: Remediate (only if high confidence)
        remediation_done = False
        if diagnosis["confidence"] > 0.8:
            print(f"🔧 Executing remediation: {diagnosis['action']}...")
            await remediate(k8s, sh, incident, diagnosis)
            remediation_done = True
            print("  ✅ Remediation applied")
        else:
            print("  ⚠️  Low confidence — escalating to human")

        # Step 4: Post status
        print("📢 Posting status to Slack...")
        await post_status(sl, incident, diagnosis, remediation_done)
        print("  Done!")


# ── Entry Point (triggered by PagerDuty webhook) ─────────────────

if __name__ == "__main__":
    import sys

    incident_id = sys.argv[1] if len(sys.argv) > 1 else "P1234567"
    asyncio.run(handle_incident(incident_id))
