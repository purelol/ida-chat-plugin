from ida_chat_history import MessageHistory


def test_session_metadata_and_listing(tmp_path, monkeypatch):
    monkeypatch.setattr(MessageHistory, "BASE_DIR", tmp_path)
    history = MessageHistory("/tmp/binary/sample.i64")

    session_id = history.start_new_session()
    history.append_user_message("Analyze the entry point")
    history.append_assistant_message("Working on it")
    history.record_export_path("/tmp/out/report.html")

    sessions = history.list_sessions()
    assert len(sessions) == 1
    session = sessions[0]
    assert session["id"] == session_id
    assert session["title"] == "Analyze the entry point"
    assert session["message_count"] == 2
    assert session["last_export_path"] == "/tmp/out/report.html"
    assert session["is_current"] is True


def test_default_title_caps_to_six_words(tmp_path, monkeypatch):
    monkeypatch.setattr(MessageHistory, "BASE_DIR", tmp_path)
    history = MessageHistory("/tmp/binary/sample.i64")

    history.start_new_session()
    history.append_user_message("Analyze the startup dispatcher for stack corruption paths now")

    assert history.get_current_session_title() == "Analyze the startup dispatcher for stack"


def test_rename_switch_and_search(tmp_path, monkeypatch):
    monkeypatch.setattr(MessageHistory, "BASE_DIR", tmp_path)
    history = MessageHistory("/tmp/binary/sample.i64")
    first = history.start_new_session()
    history.append_user_message("first")

    second = history.start_new_session()
    history.append_user_message("second")
    history.rename_session(first, "Recovered startup flow")

    assert history.switch_session(first) is True
    assert history.get_current_session_title() == "Recovered startup flow"

    filtered = history.list_sessions(query="startup")
    assert [item["id"] for item in filtered] == [first]
    assert history.switch_session(second) is True


def test_session_display_items_include_script_and_output(tmp_path, monkeypatch):
    monkeypatch.setattr(MessageHistory, "BASE_DIR", tmp_path)
    history = MessageHistory("/tmp/binary/sample.i64")
    session_id = history.start_new_session()
    history.append_user_message("show me the imports")
    history.append_tool_use("Read", {"file_path": "/tmp/file"})
    history.append_script_execution("print(db.module)", "sample.exe")
    items = history.get_session_display_items(session_id)

    kinds = [item["kind"] for item in items]
    assert "user" in kinds
    assert "tool" in kinds
    assert "script" in kinds
    assert "output" in kinds


def test_delete_session_updates_current_session(tmp_path, monkeypatch):
    monkeypatch.setattr(MessageHistory, "BASE_DIR", tmp_path)
    history = MessageHistory("/tmp/binary/sample.i64")
    first = history.start_new_session()
    history.append_user_message("first")

    second = history.start_new_session()
    history.append_user_message("second")

    assert history.delete_session(second) is True
    assert history.get_current_session_id() == first

    sessions = history.list_sessions()
    assert [item["id"] for item in sessions] == [first]
