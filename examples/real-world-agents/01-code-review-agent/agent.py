"""
Code Review Agent
=================
Multi-agent system that automatically reviews pull requests.

Architecture:
  - Agent 1 (Planner): decides which files need deep review
  - Agent 2 (Reviewer): reads code, checks style, finds bugs
  - Agent 3 (Tester): runs test suite, reports coverage delta

MCP servers used:
  - github       → fetch PR diffs, post review comments
  - filesystem   → read/write local checkout
  - shell        → run tests, linters, build commands
  - sqlite       → track review history, avoid re-reviewing
"""

import asyncio
import json
from dataclasses import dataclass
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from anthropic import Anthropic

# ── MCP Server Connections ──────────────────────────────────────────

SERVERS = {
    "github": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-github"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_EXAMPLE_DO_NOT_USE"},
    ),
    "filesystem": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/"],  # ← BUG: root access
    ),
    "shell": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-shell"],
    ),
    "review-db": StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-sqlite", "--db-path", "/tmp/reviews.db"],
    ),
}


@dataclass
class PullRequest:
    owner: str
    repo: str
    number: int
    files: list[str]


@dataclass
class ReviewComment:
    path: str
    line: int
    body: str
    severity: str  # "critical" | "warning" | "suggestion"


# ── Agent 1: Planner ────────────────────────────────────────────────

async def plan_review(github_session: ClientSession, pr: PullRequest) -> list[str]:
    """Fetch PR diff and decide which files need deep review."""

    # Get the list of changed files
    result = await github_session.call_tool(
        "get_pull_request_files",
        arguments={"owner": pr.owner, "repo": pr.repo, "pull_number": pr.number},
    )
    changed_files = json.loads(result.content[0].text)

    # Use Claude to triage which files matter
    client = Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system="You are a code review planner. Given a list of changed files, "
               "return a JSON array of files that need security-focused review. "
               "Prioritize: auth, database, API routes, config. Skip: tests, docs, assets.",
        messages=[{"role": "user", "content": json.dumps(changed_files)}],
    )

    files_to_review = json.loads(response.content[0].text)
    return files_to_review


# ── Agent 2: Reviewer ──────────────────────────────────────────────

async def review_file(
    fs_session: ClientSession,
    file_path: str,
    pr: PullRequest,
) -> list[ReviewComment]:
    """Read a file and produce review comments using Claude."""

    # Read the file content from the local checkout
    result = await fs_session.call_tool(
        "read_file",
        arguments={"path": f"/tmp/checkout/{pr.repo}/{file_path}"},
    )
    file_content = result.content[0].text

    # Ask Claude to review the code
    client = Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system="""You are a senior security-focused code reviewer.
Review the code and return a JSON array of review comments:
[{"path": "file.py", "line": 42, "body": "SQL injection risk here", "severity": "critical"}]

Focus on:
- SQL injection, command injection, path traversal
- Missing authentication/authorization checks
- Hardcoded secrets or credentials
- Unbounded user input flowing to dangerous sinks
- Race conditions in concurrent code""",
        messages=[{
            "role": "user",
            "content": f"File: {file_path}\n\n```\n{file_content}\n```",
        }],
    )

    comments_data = json.loads(response.content[0].text)
    return [ReviewComment(**c) for c in comments_data]


# ── Agent 3: Test Runner ───────────────────────────────────────────

async def run_tests(
    shell_session: ClientSession,
    pr: PullRequest,
) -> dict:
    """Run the test suite and return results."""

    repo_dir = f"/tmp/checkout/{pr.repo}"

    # Install dependencies
    await shell_session.call_tool(
        "run_command",
        arguments={"command": f"cd {repo_dir} && npm install --quiet"},
    )

    # Run tests with coverage
    result = await shell_session.call_tool(
        "run_command",
        # ← BUG: arbitrary shell execution, no sandboxing
        arguments={"command": f"cd {repo_dir} && npm test -- --coverage --json"},
    )
    test_output = json.loads(result.content[0].text)

    # Run linter
    lint_result = await shell_session.call_tool(
        "run_command",
        arguments={"command": f"cd {repo_dir} && npx eslint . --format json"},
    )

    return {
        "tests": test_output,
        "lint": json.loads(lint_result.content[0].text),
    }


# ── Orchestrator ───────────────────────────────────────────────────

async def post_review(
    github_session: ClientSession,
    db_session: ClientSession,
    pr: PullRequest,
    comments: list[ReviewComment],
    test_results: dict,
):
    """Post review comments to GitHub and record in the tracking DB."""

    # Post each comment to the PR
    for comment in comments:
        await github_session.call_tool(
            "create_pull_request_review_comment",
            arguments={
                "owner": pr.owner,
                "repo": pr.repo,
                "pull_number": pr.number,
                "path": comment.path,
                "line": comment.line,
                "body": f"**[{comment.severity.upper()}]** {comment.body}",
            },
        )

    # Record the review in our tracking database
    await db_session.call_tool(
        "execute_query",
        # ← BUG: raw string interpolation into SQL
        arguments={
            "query": f"""
                INSERT INTO reviews (repo, pr_number, comments_count, status)
                VALUES ('{pr.repo}', {pr.number}, {len(comments)}, 'completed')
            """
        },
    )


async def review_pull_request(pr: PullRequest):
    """Full review pipeline: plan → review files → run tests → post."""

    async with (
        stdio_client(SERVERS["github"]) as (gh_read, gh_write),
        stdio_client(SERVERS["filesystem"]) as (fs_read, fs_write),
        stdio_client(SERVERS["shell"]) as (sh_read, sh_write),
        stdio_client(SERVERS["review-db"]) as (db_read, db_write),
    ):
        gh = ClientSession(gh_read, gh_write)
        fs = ClientSession(fs_read, fs_write)
        sh = ClientSession(sh_read, sh_write)
        db = ClientSession(db_read, db_write)

        await asyncio.gather(
            gh.initialize(), fs.initialize(),
            sh.initialize(), db.initialize(),
        )

        # Clone the PR branch
        await sh.call_tool(
            "run_command",
            arguments={
                "command": (
                    f"git clone https://github.com/{pr.owner}/{pr.repo}.git "
                    f"/tmp/checkout/{pr.repo} && "
                    f"cd /tmp/checkout/{pr.repo} && "
                    f"git fetch origin pull/{pr.number}/head:pr-{pr.number} && "
                    f"git checkout pr-{pr.number}"
                )
            },
        )

        # Agent 1: Plan
        files_to_review = await plan_review(gh, pr)
        print(f"📋 Planner selected {len(files_to_review)} files for review")

        # Agent 2: Review each file in parallel
        review_tasks = [review_file(fs, f, pr) for f in files_to_review]
        all_comments = []
        for comments in await asyncio.gather(*review_tasks):
            all_comments.extend(comments)
        print(f"🔍 Reviewer found {len(all_comments)} issues")

        # Agent 3: Run tests
        test_results = await run_tests(sh, pr)
        passed = test_results["tests"].get("numPassedTests", 0)
        failed = test_results["tests"].get("numFailedTests", 0)
        print(f"🧪 Tests: {passed} passed, {failed} failed")

        # Post results
        await post_review(gh, db, pr, all_comments, test_results)
        print(f"✅ Posted {len(all_comments)} review comments to PR #{pr.number}")


# ── Entry Point ────────────────────────────────────────────────────

if __name__ == "__main__":
    pr = PullRequest(
        owner="acme-corp",
        repo="backend-api",
        number=142,
        files=[],
    )
    asyncio.run(review_pull_request(pr))
