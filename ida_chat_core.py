"""
IDA Chat Core - Shared foundation for CLI and Plugin.

This module contains the common Agent SDK integration, script execution,
and message processing used by both the CLI and IDA plugin.
"""

from collections import deque
from contextlib import contextmanager
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from io import StringIO
from pathlib import Path
from typing import Awaitable, Callable, Protocol, TYPE_CHECKING, cast
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)
from claude_agent_sdk.types import HookContext, HookInput, HookJSONOutput, PreToolUseHookInput, SdkBeta
from ida_chat_export import render_transcript_html
from ida_chat_support import (
    ConnectionTestResult,
    DiagnosticReport,
    PromptContext,
    ScriptApprovalRequest,
    ScriptDecision,
    build_augmented_prompt,
    build_locale_env_summary,
    build_redaction_map,
    classify_script_risk,
    find_claude_cli_path,
    format_script_preview,
    normalize_error_message,
    redact_text_paths,
    summarize_tool_use,
)

if TYPE_CHECKING:
    from ida_chat_history import MessageHistory

# Set up debug logging to file
LOG_FILE = Path("/tmp/ida-chat.log")
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8"),
    ]
)
logger = logging.getLogger("ida-chat")


# Project directory for agent SDK (contains PROMPT.md, USAGE.md, API_REFERENCE.md)
PROJECT_DIR = Path(__file__).parent.resolve() / "project"

# Regex to extract <idascript>...</idascript> blocks
IDASCRIPT_PATTERN = re.compile(r"<idascript>(.*?)</idascript>", re.DOTALL)

# Prompt file locations
PROMPT_FILE = PROJECT_DIR / "PROMPT.md"
IDA_UI_FILE = PROJECT_DIR / "IDA.md"
USAGE_FILE = PROJECT_DIR / "USAGE.md"
API_REFERENCE_FILE = PROJECT_DIR / "API_REFERENCE.md"


def _resolve_tool_path(file_path: str) -> Path:
    """Resolve tool paths relative to the Claude project directory."""
    candidate = Path(file_path).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_DIR / candidate
    return candidate.resolve()


def _build_sdk_env() -> dict[str, str]:
    """Force a UTF-8-capable environment for the Claude subprocess."""
    env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }

    lang = os.environ.get("LANG", "")
    lc_all = os.environ.get("LC_ALL", "")
    if "utf-8" not in lang.lower() and "utf8" not in lang.lower():
        env["LANG"] = "en_US.UTF-8"
    if "utf-8" not in lc_all.lower() and "utf8" not in lc_all.lower():
        env["LC_ALL"] = "en_US.UTF-8"

    return env


def _get_auth_mode() -> str:
    """Report the active authentication mode for diagnostics."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "api_key"
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return "oauth"
    return "system"


def _probe_claude_version(cli_path: str | None = None) -> tuple[str, str]:
    """Best-effort CLI path/version lookup for diagnostics."""
    resolved_path = cli_path or find_claude_cli_path()
    if not resolved_path:
        return "", ""
    try:
        result = subprocess.run(
            [resolved_path, "-v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
        )
    except Exception:
        return resolved_path, ""
    version_output = (result.stdout or result.stderr or "").strip()
    return resolved_path, version_output


class IDAChatRuntimeError(RuntimeError):
    """Runtime error that carries normalized diagnostics."""

    def __init__(self, diagnostics: DiagnosticReport):
        super().__init__(diagnostics.short_message)
        self.diagnostics = diagnostics


def _load_system_prompt() -> str:
    """Load the system prompt from PROMPT.md.

    If running inside IDA Pro (IDA_CHAT_INSIDE_IDA env var is set),
    also appends IDA.md which contains the user interaction API.
    """
    prompt_parts: list[str] = []

    if PROMPT_FILE.exists():
        prompt_parts.append(PROMPT_FILE.read_text(encoding="utf-8"))
    else:
        logger.warning(f"PROMPT.md not found at {PROMPT_FILE}")
        prompt_parts.append(
            "You have access to an open IDA database via the `db` variable. Use <idascript> tags for code."
        )

    # Append IDA UI interaction API when running inside IDA
    if os.environ.get("IDA_CHAT_INSIDE_IDA") == "1":
        if IDA_UI_FILE.exists():
            logger.info("Running inside IDA - appending IDA.md to system prompt")
            prompt_parts.append(IDA_UI_FILE.read_text(encoding="utf-8"))
        else:
            logger.warning(f"IDA.md not found at {IDA_UI_FILE}")

    for extra_file, label in (
        (USAGE_FILE, "USAGE.md"),
        (API_REFERENCE_FILE, "API_REFERENCE.md"),
    ):
        if extra_file.exists():
            prompt_parts.append(extra_file.read_text(encoding="utf-8"))
        else:
            logger.warning(f"{label} not found at {extra_file}")

    return "\n\n".join(part for part in prompt_parts if part)


async def _restrict_file_access(
    input_data: HookInput,
    _tool_use_id: str | None,
    _context: HookContext,
) -> HookJSONOutput:
    """Hook to block file operations outside PROJECT_DIR."""
    if input_data['hook_event_name'] != 'PreToolUse':
        return {}

    pre_tool_input = cast(PreToolUseHookInput, input_data)
    tool_input = pre_tool_input['tool_input']

    # Get the path being accessed (different tools use different param names)
    file_path = tool_input.get('file_path') or tool_input.get('path') or ''

    if file_path:
        # Resolve to absolute path
        resolved = _resolve_tool_path(str(file_path))

        # Check if it's inside PROJECT_DIR
        try:
            resolved.relative_to(PROJECT_DIR)
        except ValueError:
            # Path is outside PROJECT_DIR
            logger.warning(f"Blocked file access outside PROJECT_DIR: {file_path}")
            return {
                'hookSpecificOutput': {
                    'hookEventName': pre_tool_input['hook_event_name'],
                    'permissionDecision': 'deny',
                    'permissionDecisionReason': 'File access restricted to project directory'
                }
            }

    return {}


def _prepare_transcript_source(
    session_file: Path,
    redact_paths: bool,
    binary_path: str | None,
) -> Path:
    """Return the session file to feed into transcript generation."""
    if not redact_paths:
        return session_file

    redaction_map = build_redaction_map(binary_path)
    redacted_text = redact_text_paths(session_file.read_text(encoding="utf-8"), redaction_map)
    tmp_file = Path(cast(str, tempfile.mkdtemp())) / session_file.name
    tmp_file.write_text(redacted_text, encoding="utf-8")
    return tmp_file


def _clear_generated_transcript_files(
    output_dir: Path,
    *,
    remove_index: bool = False,
) -> None:
    """Delete stale transcript HTML files before regenerating them."""
    if not output_dir.exists():
        return

    if remove_index:
        index_html = output_dir / "index.html"
        if index_html.exists():
            index_html.unlink()

    for page_file in output_dir.glob("page-*.html"):
        page_file.unlink()


@contextmanager
def _prepared_transcript_source(
    session_file: Path,
    redact_paths: bool,
    binary_path: str | None,
):
    """Yield a transcript source path and clean up redacted temp files."""
    if not redact_paths:
        yield session_file
        return

    source_session = _prepare_transcript_source(session_file, redact_paths, binary_path)
    try:
        yield source_session
    finally:
        shutil.rmtree(source_session.parent, ignore_errors=True)


def export_transcript(
    session_file: Path,
    output_path: Path,
    *,
    redact_paths: bool = False,
    binary_path: str | None = None,
) -> None:
    """Export a chat session to a single standalone HTML file."""
    if not session_file.exists():
        raise FileNotFoundError(f"Session file not found: {session_file}")

    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    _clear_generated_transcript_files(output_dir)

    with _prepared_transcript_source(session_file, redact_paths, binary_path) as source_session:
        html_output = render_transcript_html(
            source_session,
            metadata_file=session_file,
            binary_path=binary_path,
            paths_redacted=redact_paths,
        )
        output_path.write_text(html_output, encoding="utf-8")

    logger.info(f"Exported transcript to {output_path}")


def export_transcript_to_dir(
    session_file: Path,
    output_dir: Path,
    *,
    redact_paths: bool = False,
    binary_path: str | None = None,
) -> Path:
    """Export a chat session to `output_dir/index.html` as a single HTML file."""
    if not session_file.exists():
        raise FileNotFoundError(f"Session file not found: {session_file}")

    output_dir.mkdir(parents=True, exist_ok=True)
    _clear_generated_transcript_files(output_dir, remove_index=True)
    index_html = output_dir / "index.html"
    export_transcript(
        session_file,
        index_html,
        redact_paths=redact_paths,
        binary_path=binary_path,
    )
    logger.info(f"Exported transcript to {index_html}")
    return index_html


async def test_claude_connection(
    model: str | None = None,
    betas: list[str] | None = None,
) -> ConnectionTestResult:
    """Test Claude connectivity with a fun prompt.

    This is a lightweight test that doesn't require a database or full
    agent configuration. Used by the onboarding panel to verify setup.

    Returns:
        Tuple of (success, message):
        - On success: (True, Claude's joke response)
        - On failure: (False, error message)
    """
    logger.info("Testing Claude connection...")

    stderr_tail: deque[str] = deque(maxlen=25)

    def capture_stderr(line: str) -> None:
        stderr_tail.append(line)

    options = ClaudeAgentOptions(
        cwd=str(PROJECT_DIR),
        permission_mode="bypassPermissions",
        allowed_tools=[],  # No tools needed for simple test
        model=model,
        betas=cast(list[SdkBeta], list(betas or [])),
        env=_build_sdk_env(),
        stderr=capture_stderr,
    )

    client = ClaudeSDKClient(options=options)
    try:
        await client.connect()
        await client.query(
            "Reply with exactly one sentence that starts with the word 'pong' "
            "followed by a short joke about reverse engineering."
        )

        response_text = ""
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        response_text += block.text

        await client.disconnect()
        logger.info(f"Connection test response: {response_text[:100]}...")

        # Verify pong is present — any error/auth message will never contain it.
        if "pong" not in response_text.lower():
            short = normalize_error_message(response_text.strip() or "No response received.")
            cli_path, version_output = _probe_claude_version()
            diagnostics = DiagnosticReport(
                phase="test",
                short_message=short,
                raw_error=response_text.strip(),
                cli_path=cli_path,
                version_output=version_output,
                cwd=str(PROJECT_DIR),
                auth_mode=_get_auth_mode(),
                locale_env=build_locale_env_summary({**os.environ, **_build_sdk_env()}),
                stderr_tail=list(stderr_tail),
            )
            return ConnectionTestResult(False, short, diagnostics)

        return ConnectionTestResult(True, response_text.strip())

    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        cli_path, version_output = _probe_claude_version()
        diagnostics = DiagnosticReport(
            phase="test",
            short_message=normalize_error_message(str(e)),
            raw_error=str(e),
            cli_path=cli_path,
            version_output=version_output,
            cwd=str(PROJECT_DIR),
            auth_mode=_get_auth_mode(),
            locale_env=build_locale_env_summary({**os.environ, **_build_sdk_env()}),
            stderr_tail=list(stderr_tail),
        )
        return ConnectionTestResult(False, diagnostics.short_message, diagnostics)


class ChatCallback(Protocol):
    """Protocol for handling chat output events.

    Implementations of this protocol handle the presentation layer,
    whether that's terminal output (CLI) or Qt widgets (Plugin).
    """

    def on_turn_start(self, turn: int, max_turns: int) -> None:
        """Called at the start of each agentic turn."""
        ...

    def on_thinking(self) -> None:
        """Called when the agent starts processing."""
        ...

    def on_thinking_done(self) -> None:
        """Called when the agent produces first output."""
        ...

    def on_tool_use(self, tool_name: str, details: str) -> None:
        """Called when the agent uses a tool (Read, Glob, Grep, Skill)."""
        ...

    def on_text(self, text: str) -> None:
        """Called when the agent outputs text (excluding idascript blocks)."""
        ...

    def on_script_code(self, request: ScriptApprovalRequest) -> None:
        """Called with script preview and approval metadata."""
        ...

    def on_script_output(self, output: str) -> None:
        """Called with the output of an executed idascript."""
        ...

    def on_error(self, error: str) -> None:
        """Called when an error occurs."""
        ...

    def on_result(self, num_turns: int, cost: float | None) -> None:
        """Called when the agent finishes with stats."""
        ...


class IDAChatCore:
    """Shared chat backend for CLI and Plugin.

    Handles Agent SDK integration, message processing, and script execution.
    Implements an agentic loop that feeds script results back to the agent.
    Output is delegated to the callback for presentation.
    """

    def __init__(
        self,
        db,
        callback: ChatCallback,
        script_executor: Callable[[str], str] | None = None,
        script_approver: Callable[[ScriptApprovalRequest], Awaitable[ScriptDecision]] | None = None,
        verbose: bool = False,
        max_turns: int = 20,
        history: "MessageHistory | None" = None,
        require_script_approval: bool = False,
        model: str | None = None,
        betas: list[str] | None = None,
    ):
        """Initialize the chat core.

        Args:
            db: An open ida_domain Database instance.
            callback: Handler for output events.
            script_executor: Optional custom script executor. If None, uses
                default direct execution. Plugin can inject a thread-safe
                executor that runs on the main thread.
            script_approver: Optional async callback used when approval is required.
            verbose: If True, report additional stats.
            max_turns: Maximum agentic turns before stopping (default 20).
            history: Optional MessageHistory for persisting conversations.
            require_script_approval: Whether every generated script should pause
                for UI approval before execution.
        """
        self.db = db
        self.callback = callback
        self.verbose = verbose
        self.max_turns = max_turns
        self.history = history
        self.model = model
        self.betas: list[SdkBeta] = cast(list[SdkBeta], list(betas or []))
        self.client: ClaudeSDKClient | None = None
        self._cancelled = False
        self._script_approver = script_approver
        self.require_script_approval = require_script_approval
        self._stderr_tail: deque[str] = deque(maxlen=25)
        self._last_diagnostics: DiagnosticReport | None = None
        # Use injected executor or default to direct execution
        self._execute_script = script_executor or self._default_execute_script

    def request_cancel(self) -> None:
        """Request cancellation of the current operation."""
        self._cancelled = True
        logger.info("Cancel requested")

    def _capture_stderr(self, line: str) -> None:
        """Store the last stderr lines from the Claude subprocess."""
        self._stderr_tail.append(line)
        logger.debug(f"[claude stderr] {line}")

    def _build_diagnostics(self, phase: str, error: Exception | str) -> DiagnosticReport:
        """Create a normalized diagnostics payload from an exception."""
        cli_path, version_output = _probe_claude_version()
        raw_error = str(error)
        diagnostics = DiagnosticReport(
            phase=phase,  # type: ignore[arg-type]
            short_message=normalize_error_message(raw_error),
            raw_error=raw_error,
            cli_path=cli_path,
            version_output=version_output,
            cwd=str(PROJECT_DIR),
            auth_mode=_get_auth_mode(),
            locale_env=build_locale_env_summary({**os.environ, **_build_sdk_env()}),
            stderr_tail=list(self._stderr_tail),
        )
        self._last_diagnostics = diagnostics
        return diagnostics

    def get_last_diagnostics(self) -> DiagnosticReport | None:
        """Return the last captured diagnostics payload."""
        return self._last_diagnostics

    def _require_client(self) -> ClaudeSDKClient:
        """Return the connected SDK client or fail fast."""
        if self.client is None:
            raise RuntimeError("Client not connected. Call connect() first.")
        return self.client

    async def connect(self) -> None:
        """Initialize and connect the Agent SDK client."""
        logger.info("=" * 60)
        logger.info("Connecting to Claude Agent SDK")
        logger.info(f"CWD: {PROJECT_DIR}")
        self._stderr_tail.clear()

        options = ClaudeAgentOptions(
            cwd=str(PROJECT_DIR),
            setting_sources=["project"],
            allowed_tools=["Read", "Glob", "Grep", "Task"],
            permission_mode="bypassPermissions",
            model=self.model,
            betas=self.betas,
            env=_build_sdk_env(),
            stderr=self._capture_stderr,
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                "append": _load_system_prompt(),
            },
            hooks={
                'PreToolUse': [
                    HookMatcher(matcher='Read|Glob|Grep', hooks=[_restrict_file_access])
                ]
            },
        )

        self.client = ClaudeSDKClient(options=options)
        try:
            await self.client.connect()
            logger.info("Connected successfully")
        except Exception as error:
            raise IDAChatRuntimeError(self._build_diagnostics("connect", error)) from error

    async def disconnect(self) -> None:
        """Disconnect the Agent SDK client."""
        if self.client:
            try:
                await self.client.disconnect()
            except Exception as error:
                raise IDAChatRuntimeError(self._build_diagnostics("disconnect", error)) from error
            self.client = None

    async def interrupt(self) -> None:
        """Interrupt an in-flight request if the SDK is connected."""
        self._cancelled = True
        if not self.client:
            return
        try:
            await self.client.interrupt()
        except Exception as error:
            logger.warning(f"Interrupt failed: {error}")
            raise IDAChatRuntimeError(self._build_diagnostics("query", error)) from error

    def _default_execute_script(self, code: str) -> str:
        """Default script executor - direct execution.

        Args:
            code: Python code to execute with `db` in scope.

        Returns:
            Captured stdout output or error message.
        """
        old_stdout = sys.stdout
        sys.stdout = captured = StringIO()

        try:
            exec(code, {"db": self.db, "print": print})
            return captured.getvalue()
        except Exception as e:
            return f"Script error: {e}"
        finally:
            sys.stdout = old_stdout

    async def _decide_script(self, request: ScriptApprovalRequest) -> ScriptDecision:
        """Resolve whether a generated script should run."""
        self.callback.on_script_code(request)
        if not request.requires_approval or self._script_approver is None:
            return "approve"
        return await self._script_approver(request)

    async def _process_single_response(self) -> tuple[list[str], list[str]]:
        """Process a single agent response.

        Returns:
            Tuple of (scripts_found, script_outputs)
        """
        full_text: list[str] = []
        scripts_found: list[str] = []
        script_outputs: list[str] = []
        first_output = True
        client = self._require_client()

        async for message in client.receive_response():
            logger.debug(f"Received message type: {type(message).__name__}")

            if isinstance(message, AssistantMessage):
                logger.debug(f"AssistantMessage with {len(message.content)} blocks")
                for i, block in enumerate(message.content):
                    logger.debug(f"  Block {i}: {type(block).__name__}")

                    # Notify thinking done on first output
                    if first_output:
                        self.callback.on_thinking_done()
                        first_output = False

                    if isinstance(block, ToolUseBlock):
                        logger.info(f"TOOL USE: {block.name}")
                        logger.debug(f"  Tool input: {block.input}")

                        # Extract tool details based on tool type
                        details = summarize_tool_use(
                            block.name,
                            block.input if isinstance(block.input, dict) else {"input": str(block.input)},
                        )
                        self.callback.on_tool_use(block.name, details)

                        # Log tool use to history
                        if self.history:
                            self.history.append_tool_use(
                                block.name,
                                block.input if isinstance(block.input, dict) else {"input": str(block.input)}
                            )

                    elif isinstance(block, TextBlock):
                        text = block.text
                        logger.debug(f"  TextBlock ({len(text)} chars): {text[:100]}...")
                        full_text.append(text)

                        # Output text excluding <idascript> blocks
                        cleaned = IDASCRIPT_PATTERN.sub("", text).strip()
                        if cleaned:
                            self.callback.on_text(cleaned)
                            # Log assistant text to history
                            if self.history:
                                self.history.append_assistant_message(
                                    cleaned,
                                    model=self.model or "claude-sonnet-4-20250514",
                                )
                    else:
                        logger.warning(f"  Unknown block type: {type(block).__name__}")

            elif isinstance(message, ResultMessage):
                logger.info(f"ResultMessage: turns={message.num_turns}, cost={message.total_cost_usd}")

                # Extract scripts from the response
                if full_text:
                    combined = "".join(full_text)
                    scripts_found = IDASCRIPT_PATTERN.findall(combined)
                    logger.info(f"Found {len(scripts_found)} scripts in response")

                    # Execute each script
                    for j, script_code in enumerate(scripts_found):
                        code = script_code.strip()
                        request = ScriptApprovalRequest(
                            request_id=f"script_{uuid.uuid4().hex}",
                            code=code,
                            script_index=j + 1,
                            total_scripts=len(scripts_found),
                            risk=classify_script_risk(code),
                            preview=format_script_preview(code),
                            requires_approval=self.require_script_approval,
                        )
                        logger.debug(f"Script {j+1}:\n{code}")
                        decision = await self._decide_script(request)

                        if decision == "cancel":
                            self._cancelled = True
                            self.callback.on_error("Operation cancelled")
                            break

                        if decision == "skip":
                            output = "Script execution skipped by user."
                            script_outputs.append(output)
                            self.callback.on_script_output(output)
                            if self.history:
                                self.history.append_script_execution(code, output, is_error=False)
                            continue

                        output = self._execute_script(code)
                        logger.debug(f"Script {j+1} output:\n{output}")
                        script_outputs.append(output)
                        if output:
                            self.callback.on_script_output(output)

                        # Log script execution to history
                        if self.history:
                            self.history.append_script_execution(
                                code,
                                output,
                                is_error=output.strip().startswith("Script error:"),
                            )

                self.callback.on_result(
                    message.num_turns,
                    message.total_cost_usd,
                )
            else:
                logger.warning(f"Unknown message type: {type(message).__name__}")

        return scripts_found, script_outputs

    async def process_message(
        self,
        user_input: str,
        prompt_context: PromptContext | None = None,
    ) -> str:
        """Agentic loop - process message and continue until agent is done.

        The agent will keep working, seeing script outputs and fixing errors,
        until either:
        - It responds without any <idascript> tags (task complete)
        - Maximum turns is reached

        Args:
            user_input: The user's message/query.

        Returns:
            Combined script outputs as a string.
        """
        client = self._require_client()

        logger.info("-" * 60)
        logger.info(f"USER MESSAGE: {user_input[:200]}...")

        # Log user message to history
        if self.history:
            self.history.append_user_message(user_input)

        current_input = build_augmented_prompt(user_input, prompt_context)
        all_script_outputs: list[str] = []
        turn = 0
        self._cancelled = False

        while turn < self.max_turns:
            # Check for cancellation
            if self._cancelled:
                logger.info("Operation cancelled by user")
                self.callback.on_error("Operation cancelled")
                break
            turn += 1
            logger.info(f"=== TURN {turn}/{self.max_turns} ===")
            self.callback.on_turn_start(turn, self.max_turns)
            self.callback.on_thinking()

            # Send message to agent
            logger.debug(f"Sending to agent: {current_input[:200]}...")
            try:
                await client.query(current_input)

                # Process response and execute any scripts
                scripts_found, script_outputs = await self._process_single_response()
            except IDAChatRuntimeError:
                raise
            except Exception as error:
                raise IDAChatRuntimeError(self._build_diagnostics("query", error)) from error
            all_script_outputs.extend(script_outputs)

            if not scripts_found:
                # No scripts in response = agent is done
                logger.info("No scripts in response - agent is done")
                break

            # Feed script results back to agent for next turn
            if script_outputs:
                # Format all outputs for the agent
                formatted_outputs = []
                for i, output in enumerate(script_outputs, 1):
                    if len(scripts_found) > 1:
                        formatted_outputs.append(f"Script {i} output:\n{output}")
                    else:
                        formatted_outputs.append(output)
                current_input = "Script output:\n\n" + "\n\n".join(formatted_outputs)
                logger.debug(f"Feeding back to agent: {current_input[:200]}...")
            else:
                current_input = "Script executed successfully with no output."
                logger.debug("Script had no output, notifying agent")

        if turn >= self.max_turns:
            logger.warning(f"Reached maximum turns ({self.max_turns})")
            self.callback.on_error(f"Reached maximum turns ({self.max_turns})")

        return "\n".join(all_script_outputs) if all_script_outputs else ""
