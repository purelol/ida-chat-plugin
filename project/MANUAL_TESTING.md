# Manual IDA Smoke Tests

## Connection and diagnostics

1. Launch the plugin with valid Claude credentials and confirm the chat connects.
2. Break the Claude configuration intentionally and confirm the onboarding test shows a short error plus expandable details.
3. Restore credentials and confirm the settings test succeeds again.

## Session workflow

1. Start a new chat and send at least one prompt.
2. Confirm the session appears in the sidebar with an auto-generated title.
3. Rename the session from the sidebar and confirm the title updates in both the list and the status bar.
4. Start a new chat, then resume the previous session from the sidebar and confirm the old conversation is rehydrated.

## Script execution flow

1. Enable `Ask before running generated scripts` in settings.
2. Ask for a prompt that causes `<idascript>` generation.
3. Confirm the script preview card appears with a risk label and Approve / Skip / Cancel actions.
4. Verify each decision path:
   - `Approve`: script executes and output is appended.
   - `Skip`: the agent receives a skipped result and continues.
   - `Cancel`: the current turn stops cleanly.

## Context and export

1. Enable automatic context capture and send a prompt while a function, selection, and highlighted token are visible in IDA.
2. Confirm the answer reflects the current cursor context without manually typing it.
3. Export the active session and verify the save dialog appears.
4. With export redaction enabled, inspect the generated HTML and confirm home-directory and binary paths are redacted.
