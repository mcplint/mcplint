"""
RAG Customer Support Agent
===========================
A customer-facing support agent that:
  1. Receives a customer email/chat message
  2. Searches vector knowledge base for relevant docs
  3. Looks up customer details in the CRM
  4. Drafts a personalized reply using Claude
  5. Sends the reply via email (with human-in-the-loop approval)

Shows realistic RAG + MCP integration with multiple data sources.
"""

import asyncio
import json
from dataclasses import dataclass, field
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from anthropic import Anthropic


@dataclass
class CustomerMessage:
    customer_email: str
    subject: str
    body: str
    thread_id: str | None = None


@dataclass
class SupportContext:
    """All the context gathered before drafting a reply."""
    customer_name: str = ""
    customer_plan: str = ""
    account_age_days: int = 0
    open_tickets: int = 0
    kb_articles: list[dict] = field(default_factory=list)
    past_interactions: list[dict] = field(default_factory=list)


# ── MCP Server Connections ──────────────────────────────────────────

SERVERS = {
    "knowledge-base": StdioServerParameters(
        command="node",
        args=["./mcp-servers/kb-server/index.js"],
        env={
            "PINECONE_API_KEY": "${PINECONE_KEY}",
            "PINECONE_INDEX": "support-kb",
            "OPENAI_API_KEY": "${OPENAI_KEY}",  # for embeddings
        },
    ),
    "crm": StdioServerParameters(
        command="npx",
        args=["-y", "@acme/mcp-hubspot"],
        env={
            "HUBSPOT_API_KEY": "${HUBSPOT_KEY}",
        },
    ),
    "email": StdioServerParameters(
        command="node",
        args=["./mcp-servers/email-server/index.js"],
        env={
            "SENDGRID_API_KEY": "${SENDGRID_KEY}",
            "FROM_ADDRESS": "support@acme.com",
            "REPLY_TO": "support@acme.com",
        },
    ),
    "ticket-db": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-postgres"],
        env={
            "POSTGRES_CONNECTION_STRING": "postgresql://support_bot:EXAMPLE_PASS@tickets-db.acme.io:5432/support",
        },
    ),
    "filesystem": StdioServerParameters(
        command="npx",
        # ← BUG: mounts entire /var instead of just the templates dir
        args=["-y", "@modelcontextprotocol/server-filesystem", "/var"],
    ),
}

client = Anthropic()


# ── Step 1: Search Knowledge Base ─────────────────────────────────

async def search_knowledge_base(
    kb_session: ClientSession,
    query: str,
) -> list[dict]:
    """Semantic search across the support knowledge base."""

    result = await kb_session.call_tool(
        "semantic_search",
        arguments={
            "query": query,
            "top_k": 5,
            "namespace": "support-articles",
            "include_metadata": True,
        },
    )

    articles = json.loads(result.content[0].text)
    return [
        {
            "title": a["metadata"]["title"],
            "url": a["metadata"]["url"],
            "content": a["text"],
            "score": a["score"],
        }
        for a in articles
    ]


# ── Step 2: Look Up Customer ─────────────────────────────────────

async def lookup_customer(
    crm_session: ClientSession,
    db_session: ClientSession,
    email: str,
) -> SupportContext:
    """Pull customer info from CRM and ticket history from DB."""

    # Get customer profile from HubSpot
    crm_result = await crm_session.call_tool(
        "get_contact_by_email",
        arguments={"email": email},
    )
    contact = json.loads(crm_result.content[0].text)

    # Get their ticket history from the support DB
    # ← BUG: string interpolation into SQL — injection risk
    ticket_result = await db_session.call_tool(
        "execute_query",
        arguments={
            "query": f"""
                SELECT id, subject, status, created_at, resolution
                FROM tickets
                WHERE customer_email = '{email}'
                ORDER BY created_at DESC
                LIMIT 10
            """,
        },
    )
    tickets = json.loads(ticket_result.content[0].text)

    ctx = SupportContext(
        customer_name=contact.get("firstname", "there"),
        customer_plan=contact.get("plan", "free"),
        account_age_days=contact.get("account_age_days", 0),
        open_tickets=sum(1 for t in tickets if t["status"] == "open"),
        past_interactions=tickets,
    )
    return ctx


# ── Step 3: Draft Reply ──────────────────────────────────────────

async def draft_reply(
    message: CustomerMessage,
    context: SupportContext,
) -> str:
    """Use Claude to draft a personalized support reply."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        system=f"""You are a friendly, helpful customer support agent for Acme Inc.

Customer context:
- Name: {context.customer_name}
- Plan: {context.customer_plan}
- Account age: {context.account_age_days} days
- Open tickets: {context.open_tickets}

Relevant knowledge base articles:
{json.dumps(context.kb_articles, indent=2)}

Recent ticket history:
{json.dumps(context.past_interactions[:3], indent=2)}

Guidelines:
- Be empathetic and professional
- Reference specific KB articles with links when relevant
- If the customer is on a paid plan and has been a long-time customer, be extra accommodating
- If you can't solve the issue, escalate to a human agent
- Never expose internal systems, database queries, or implementation details""",
        messages=[{
            "role": "user",
            "content": f"Subject: {message.subject}\n\n{message.body}",
        }],
    )

    return response.content[0].text


# ── Step 4: Send Reply ───────────────────────────────────────────

async def send_reply(
    email_session: ClientSession,
    db_session: ClientSession,
    message: CustomerMessage,
    reply_text: str,
    context: SupportContext,
    auto_send: bool = False,
):
    """Send the reply (or queue for human review) and log the interaction."""

    if auto_send and context.customer_plan != "enterprise":
        # Auto-send for non-enterprise customers
        await email_session.call_tool(
            "send_email",
            arguments={
                "to": message.customer_email,
                "subject": f"Re: {message.subject}",
                "body_html": f"<p>Hi {context.customer_name},</p>\n{reply_text}",
                "reply_to_thread": message.thread_id,
            },
        )
    else:
        # Queue for human review
        print(f"📋 Queued for human review (enterprise customer)")

    # Log the interaction
    await db_session.call_tool(
        "execute_query",
        arguments={
            "query": f"""
                INSERT INTO interactions (customer_email, subject, agent_reply, auto_sent, created_at)
                VALUES ('{message.customer_email}', '{message.subject}', '{reply_text}', {auto_send}, NOW())
            """,
        },
    )


# ── Orchestrator ──────────────────────────────────────────────────

async def handle_support_message(message: CustomerMessage):
    """Full support pipeline: search → lookup → draft → send."""

    async with (
        stdio_client(SERVERS["knowledge-base"]) as (kb_r, kb_w),
        stdio_client(SERVERS["crm"]) as (crm_r, crm_w),
        stdio_client(SERVERS["email"]) as (em_r, em_w),
        stdio_client(SERVERS["ticket-db"]) as (db_r, db_w),
        stdio_client(SERVERS["filesystem"]) as (fs_r, fs_w),
    ):
        kb = ClientSession(kb_r, kb_w)
        crm = ClientSession(crm_r, crm_w)
        email = ClientSession(em_r, em_w)
        db = ClientSession(db_r, db_w)
        fs = ClientSession(fs_r, fs_w)

        for s in [kb, crm, email, db, fs]:
            await s.initialize()

        # Step 1: Search knowledge base
        print("🔍 Searching knowledge base...")
        articles = await search_knowledge_base(kb, message.body)
        print(f"  Found {len(articles)} relevant articles")

        # Step 2: Look up customer
        print("👤 Looking up customer...")
        context = await lookup_customer(crm, db, message.customer_email)
        context.kb_articles = articles
        print(f"  Customer: {context.customer_name} ({context.customer_plan} plan)")

        # Load email template from filesystem
        template_result = await fs.call_tool(
            "read_file",
            arguments={"path": "/var/app/templates/support-reply.html"},
        )

        # Step 3: Draft reply
        print("✍️  Drafting reply...")
        reply = await draft_reply(message, context)
        print(f"  Draft ready ({len(reply)} chars)")

        # Step 4: Send
        print("📤 Sending reply...")
        await send_reply(email, db, message, reply, context, auto_send=True)
        print("  ✅ Done!")

        return reply


# ── Entry Point ──────────────────────────────────────────────────

if __name__ == "__main__":
    message = CustomerMessage(
        customer_email="jane@example.com",
        subject="Can't export my data to CSV",
        body=(
            "Hi, I've been trying to export my dashboard data to CSV "
            "but the export button just spins forever. I'm on the Pro plan "
            "and this worked fine last week. Can you help?"
        ),
        thread_id="thread_abc123",
    )
    asyncio.run(handle_support_message(message))
