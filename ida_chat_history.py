"""Persistent JSONL history and metadata for IDA Chat sessions."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ida_chat_support import normalize_session_entries


class MessageHistory:
    """Manage per-binary JSONL sessions plus sidecar metadata."""

    BASE_DIR = Path.home() / ".ida-chat" / "sessions"
    VERSION = "ida-chat-1.1.0"
    DEFAULT_TITLE = "New Chat"

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.session_dir = self._get_session_dir()
        self.session_id: str | None = None
        self.session_file: Path | None = None
        self._parent_uuid: str | None = None

    def _encode_path(self, path: str) -> str:
        encoded = re.sub(r"[/\\: ]", "_", path)
        encoded = encoded.lstrip("_")
        return re.sub(r"_+", "_", encoded)

    def _get_session_dir(self) -> Path:
        return self.BASE_DIR / self._encode_path(self.binary_path)

    def _session_path(self, session_id: str) -> Path:
        return self.session_dir / f"{session_id}.jsonl"

    def _metadata_path(self, session_id: str) -> Path:
        return self.session_dir / f"{session_id}.meta.json"

    def _generate_uuid(self) -> str:
        return str(uuid.uuid4())

    def _get_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _create_base_entry(self) -> dict[str, Any]:
        msg_uuid = self._generate_uuid()
        return {
            "uuid": msg_uuid,
            "parentUuid": self._parent_uuid,
            "sessionId": self.session_id,
            "timestamp": self._get_timestamp(),
            "version": self.VERSION,
            "cwd": str(Path(self.binary_path).parent),
            "isSidechain": False,
            "userType": "external",
        }

    def _default_title_from_text(self, text: str) -> str:
        cleaned = " ".join(text.strip().split())
        if not cleaned:
            return self.DEFAULT_TITLE
        words = cleaned.split()
        if not words:
            return self.DEFAULT_TITLE
        return " ".join(words[:6])

    def _default_metadata(self, session_id: str, created_at: str | None = None) -> dict[str, Any]:
        ts = created_at or self._get_timestamp()
        return {
            "id": session_id,
            "title": self.DEFAULT_TITLE,
            "created_at": ts,
            "updated_at": ts,
            "last_export_path": None,
        }

    def _load_metadata(self, session_id: str) -> dict[str, Any]:
        path = self._metadata_path(session_id)
        if not path.exists():
            return self._default_metadata(session_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return self._default_metadata(session_id)
        metadata = self._default_metadata(session_id)
        metadata.update(data)
        return metadata

    def _save_metadata(self, session_id: str, metadata: dict[str, Any]) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._metadata_path(session_id).write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _touch_metadata(self, session_id: str, **changes: Any) -> None:
        metadata = self._load_metadata(session_id)
        metadata.update(changes)
        metadata["updated_at"] = self._get_timestamp()
        self._save_metadata(session_id, metadata)

    def _read_last_uuid(self, session_file: Path) -> str | None:
        if not session_file.exists():
            return None
        last_uuid = None
        with open(session_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last_uuid = entry.get("uuid") or last_uuid
        return last_uuid

    def _read_session_summary(self, session_file: Path) -> dict[str, Any]:
        first_user_message = None
        first_timestamp = None
        message_count = 0

        if not session_file.exists():
            return {
                "first_message": "(empty)",
                "timestamp": None,
                "message_count": 0,
            }

        with open(session_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                message_count += 1
                if first_timestamp is None:
                    first_timestamp = entry.get("timestamp")

                if first_user_message is None and entry.get("type") == "user":
                    message = entry.get("message", {})
                    content = message.get("content", [])
                    if isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "text":
                                first_user_message = item.get("text", "")[:100]
                                break
                    elif isinstance(content, str):
                        first_user_message = content[:100]

        return {
            "first_message": first_user_message or "(empty)",
            "timestamp": first_timestamp,
            "message_count": message_count,
        }

    def start_new_session(self, title: str | None = None) -> str:
        self.session_id = self._generate_uuid()
        self._parent_uuid = None
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.session_file = self._session_path(self.session_id)
        self.session_file.touch(exist_ok=True)
        metadata = self._default_metadata(self.session_id)
        if title:
            metadata["title"] = title
        self._save_metadata(self.session_id, metadata)
        return self.session_id

    def switch_session(self, session_id: str) -> bool:
        session_file = self._session_path(session_id)
        if not session_file.exists():
            return False
        self.session_id = session_id
        self.session_file = session_file
        self._parent_uuid = self._read_last_uuid(session_file)
        metadata = self._load_metadata(session_id)
        metadata["updated_at"] = metadata.get("updated_at") or self._get_timestamp()
        self._save_metadata(session_id, metadata)
        return True

    def rename_session(self, session_id: str, title: str) -> bool:
        session_file = self._session_path(session_id)
        if not session_file.exists():
            return False
        self._touch_metadata(session_id, title=title.strip() or self.DEFAULT_TITLE)
        return True

    def delete_session(self, session_id: str) -> bool:
        """Delete a session transcript and its metadata sidecar."""
        session_file = self._session_path(session_id)
        metadata_file = self._metadata_path(session_id)
        if not session_file.exists() and not metadata_file.exists():
            return False

        was_current = session_id == self.session_id

        if session_file.exists():
            session_file.unlink()
        if metadata_file.exists():
            metadata_file.unlink()

        if was_current:
            self.session_id = None
            self.session_file = None
            self._parent_uuid = None
            remaining = self.list_sessions()
            if remaining:
                self.switch_session(str(remaining[0]["id"]))

        return True

    def record_export_path(self, export_path: str, session_id: str | None = None) -> None:
        target_id = session_id or self.session_id
        if not target_id:
            return
        self._touch_metadata(target_id, last_export_path=export_path)

    def get_current_session_id(self) -> str | None:
        return self.session_id

    def get_current_session_title(self) -> str:
        if not self.session_id:
            return self.DEFAULT_TITLE
        return str(self._load_metadata(self.session_id).get("title") or self.DEFAULT_TITLE)

    def append_user_message(self, content: str) -> str:
        if not self.session_file:
            raise RuntimeError("No active session. Call start_new_session() first.")

        entry = self._create_base_entry()
        entry["type"] = "user"
        entry["message"] = {
            "role": "user",
            "content": [{"type": "text", "text": content}],
        }

        self._write_entry(entry)

        if self.session_id:
            metadata = self._load_metadata(self.session_id)
            if metadata.get("title") in {None, "", self.DEFAULT_TITLE}:
                metadata["title"] = self._default_title_from_text(content)
                metadata["updated_at"] = self._get_timestamp()
                self._save_metadata(self.session_id, metadata)

        return entry["uuid"]

    def append_assistant_message(
        self,
        content: str,
        model: str = "claude-sonnet-4-20250514",
        usage: dict[str, Any] | None = None,
    ) -> str:
        if not self.session_file:
            raise RuntimeError("No active session. Call start_new_session() first.")

        entry = self._create_base_entry()
        entry["type"] = "assistant"
        entry["message"] = {
            "id": f"msg_{self._generate_uuid()}",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": content}],
            "stop_reason": "end_turn",
        }
        if usage:
            entry["message"]["usage"] = usage

        self._write_entry(entry)
        return entry["uuid"]

    def append_tool_use(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_use_id: str | None = None,
    ) -> str:
        if not self.session_file:
            raise RuntimeError("No active session. Call start_new_session() first.")

        resolved_tool_use_id = tool_use_id or f"toolu_{self._generate_uuid()}"
        entry = self._create_base_entry()
        entry["type"] = "assistant"
        entry["message"] = {
            "id": f"msg_{self._generate_uuid()}",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [{
                "type": "tool_use",
                "id": resolved_tool_use_id,
                "name": tool_name,
                "input": tool_input,
            }],
            "stop_reason": "tool_use",
        }
        self._write_entry(entry)
        return entry["uuid"]

    def append_tool_result(
        self,
        tool_use_id: str,
        result: str | list[dict[str, Any]],
        is_error: bool = False,
    ) -> str:
        if not self.session_file:
            raise RuntimeError("No active session. Call start_new_session() first.")

        content = result if not isinstance(result, str) else result
        entry = self._create_base_entry()
        entry["type"] = "user"
        entry["message"] = {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
                "is_error": is_error,
            }],
        }
        self._write_entry(entry)
        return entry["uuid"]

    def append_thinking(self, thinking: str) -> str:
        if not self.session_file:
            raise RuntimeError("No active session. Call start_new_session() first.")

        entry = self._create_base_entry()
        entry["type"] = "assistant"
        entry["message"] = {
            "id": f"msg_{self._generate_uuid()}",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [{"type": "thinking", "thinking": thinking}],
        }
        self._write_entry(entry)
        return entry["uuid"]

    def append_system_message(
        self,
        content: str,
        level: str = "info",
        subtype: str | None = None,
    ) -> str:
        if not self.session_file:
            raise RuntimeError("No active session. Call start_new_session() first.")

        entry = self._create_base_entry()
        entry["type"] = "system"
        entry["content"] = content
        entry["level"] = level
        if subtype:
            entry["subtype"] = subtype
        self._write_entry(entry)
        return entry["uuid"]

    def append_script_execution(
        self,
        code: str,
        output: str,
        is_error: bool = False,
    ) -> str:
        tool_use_id = f"toolu_{self._generate_uuid()}"
        self.append_tool_use(
            tool_name="IDAPythonExec",
            tool_input={"code": code},
            tool_use_id=tool_use_id,
        )
        return self.append_tool_result(
            tool_use_id=tool_use_id,
            result=output,
            is_error=is_error,
        )

    def _write_entry(self, entry: dict[str, Any]) -> None:
        if not self.session_file or not self.session_id:
            raise RuntimeError("No active session. Call start_new_session() first.")

        self.session_dir.mkdir(parents=True, exist_ok=True)
        with open(self.session_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self._parent_uuid = entry["uuid"]
        self._touch_metadata(self.session_id)

    def load_session(self, session_id: str) -> list[dict[str, Any]]:
        session_file = self._session_path(session_id)
        if not session_file.exists():
            return []

        messages: list[dict[str, Any]] = []
        with open(session_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    messages.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return messages

    def get_session_display_items(self, session_id: str) -> list[dict[str, Any]]:
        return normalize_session_entries(self.load_session(session_id))

    def list_sessions(self, query: str | None = None) -> list[dict[str, Any]]:
        if not self.session_dir.exists():
            return []

        normalized_query = (query or "").strip().lower()
        sessions: list[dict[str, Any]] = []

        for session_file in self.session_dir.glob("*.jsonl"):
            session_id = session_file.stem
            summary = self._read_session_summary(session_file)
            metadata = self._load_metadata(session_id)

            session = {
                "id": session_id,
                "title": metadata.get("title") or self.DEFAULT_TITLE,
                "first_message": summary["first_message"],
                "timestamp": summary["timestamp"],
                "created_at": metadata.get("created_at"),
                "updated_at": metadata.get("updated_at") or summary["timestamp"],
                "message_count": summary["message_count"],
                "is_current": session_id == self.session_id,
                "last_export_path": metadata.get("last_export_path"),
            }

            if normalized_query:
                haystack = " ".join(
                    str(session[key] or "")
                    for key in ("title", "first_message", "id")
                ).lower()
                if normalized_query not in haystack:
                    continue

            sessions.append(session)

        sessions.sort(key=lambda item: item.get("updated_at") or "", reverse=True)
        return sessions

    def get_all_user_messages(self) -> list[str]:
        if not self.session_dir.exists():
            return []

        messages_with_time: list[tuple[str, str]] = []
        for session_file in self.session_dir.glob("*.jsonl"):
            with open(session_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("type") != "user":
                        continue
                    message = entry.get("message", {})
                    content = message.get("content", [])
                    timestamp = entry.get("timestamp", "")
                    text = None
                    if isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "text":
                                text = item.get("text", "")
                                break
                    elif isinstance(content, str):
                        text = content
                    if text:
                        messages_with_time.append((timestamp, text))

        messages_with_time.sort(key=lambda item: item[0])
        seen: set[str] = set()
        unique_messages: list[str] = []
        for _, content in messages_with_time:
            if content not in seen:
                seen.add(content)
                unique_messages.append(content)
        return unique_messages
