"""
Data Analyst Agent
==================
An agent that a product manager talks to in Claude Desktop.
It queries production databases, generates reports, saves CSVs,
and emails them to stakeholders.

This is the "just make it work" config that startups actually ship.

MCP servers used:
  - postgres (prod)    → run analytics queries against production
  - postgres (warehouse) → run heavy aggregations on the data warehouse
  - filesystem         → write CSV/chart outputs
  - shell              → run Python scripts for data viz
  - email              → send reports to stakeholders
"""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from anthropic import Anthropic


# ── MCP Server Connections ──────────────────────────────────────────

SERVERS = {
    "prod-db": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-postgres"],
        env={
            # ← BUG: production credentials hardcoded
            "POSTGRES_CONNECTION_STRING": "postgresql://analyst:EXAMPLE_PASS@prod-db.acme.io:5432/production",
        },
    ),
    "warehouse": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-postgres"],
        env={
            "POSTGRES_CONNECTION_STRING": "${WAREHOUSE_DB_URL}",
        },
    ),
    "filesystem": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/home/analyst/reports"],
    ),
    "shell": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-shell"],
    ),
    "email": StdioServerParameters(
        command="node",
        args=["./mcp-servers/email-server/index.js"],
        env={
            "SENDGRID_API_KEY": "SG.EXAMPLE_KEY_DO_NOT_USE.abcdefghijklmnop",
            "FROM_ADDRESS": "reports@acme.com",
        },
    ),
}

client = Anthropic()


# ── Conversational Agent Loop ──────────────────────────────────────

class DataAnalystAgent:
    """
    A conversational agent that uses Claude to interpret natural-language
    data questions, translates them to SQL, runs them, and formats results.
    """

    def __init__(self, sessions: dict[str, ClientSession]):
        self.sessions = sessions
        self.conversation: list[dict] = []
        self.system_prompt = """You are a data analyst assistant with access to:
- prod-db: production PostgreSQL (users, orders, products, payments tables)
- warehouse: analytics data warehouse (events, metrics, cohorts tables)
- filesystem: write reports to /home/analyst/reports/
- shell: run Python scripts for data visualization
- email: send reports to team members

When the user asks a data question:
1. Write SQL to answer it (prefer warehouse for heavy aggregations)
2. Run the query using the appropriate database tool
3. Summarize the results in plain language
4. If asked, save as CSV or generate a chart

IMPORTANT: Always use parameterized queries. Never interpolate user input into SQL.
(Note: the MCP server doesn't actually support parameterized queries — this is a gap.)
"""

    async def handle_message(self, user_message: str) -> str:
        self.conversation.append({"role": "user", "content": user_message})

        # Gather available tools from all MCP sessions
        all_tools = []
        tool_session_map = {}
        for name, session in self.sessions.items():
            tools = await session.list_tools()
            for tool in tools.tools:
                prefixed_name = f"{name}__{tool.name}"
                all_tools.append({
                    "name": prefixed_name,
                    "description": f"[{name}] {tool.description}",
                    "input_schema": tool.inputSchema,
                })
                tool_session_map[prefixed_name] = (session, tool.name)

        # Call Claude with tools
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=self.system_prompt,
            tools=all_tools,
            messages=self.conversation,
        )

        # Process tool calls in a loop until Claude gives a final answer
        while response.stop_reason == "tool_use":
            tool_results = []

            for block in response.content:
                if block.type == "tool_use":
                    session, real_name = tool_session_map[block.name]
                    result = await session.call_tool(real_name, arguments=block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result.content[0].text,
                    })

            self.conversation.append({"role": "assistant", "content": response.content})
            self.conversation.append({"role": "user", "content": tool_results})

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=self.system_prompt,
                tools=all_tools,
                messages=self.conversation,
            )

        # Extract final text response
        final_text = "".join(
            block.text for block in response.content if hasattr(block, "text")
        )
        self.conversation.append({"role": "assistant", "content": final_text})
        return final_text


# ── Example Conversation ───────────────────────────────────────────

async def main():
    async with (
        stdio_client(SERVERS["prod-db"]) as (db_r, db_w),
        stdio_client(SERVERS["warehouse"]) as (wh_r, wh_w),
        stdio_client(SERVERS["filesystem"]) as (fs_r, fs_w),
        stdio_client(SERVERS["shell"]) as (sh_r, sh_w),
        stdio_client(SERVERS["email"]) as (em_r, em_w),
    ):
        sessions = {
            "prod-db": ClientSession(db_r, db_w),
            "warehouse": ClientSession(wh_r, wh_w),
            "filesystem": ClientSession(fs_r, fs_w),
            "shell": ClientSession(sh_r, sh_w),
            "email": ClientSession(em_r, em_w),
        }
        for s in sessions.values():
            await s.initialize()

        agent = DataAnalystAgent(sessions)

        # Simulate a PM conversation
        queries = [
            "What were our top 10 products by revenue last month?",
            "Show me the weekly active user trend for the past 12 weeks",
            "Save that as a CSV and email it to pm-team@acme.com",
            "Compare our conversion rate this quarter vs last quarter, broken down by channel",
            "Generate a bar chart of revenue by product category and save it to reports/",
        ]

        for query in queries:
            print(f"\n{'='*60}")
            print(f"PM: {query}")
            print(f"{'='*60}")
            response = await agent.handle_message(query)
            print(f"\nAnalyst Agent: {response}")


if __name__ == "__main__":
    asyncio.run(main())
