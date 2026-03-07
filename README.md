<div align="center">
  <img src="images/ida.webp" alt="IDA Pro" width="96" height="96">

  <h1>IDA Chat Plugin</h1>

  <p>
    <strong>AI-powered chat interface for IDA Pro — powered by Claude</strong>
  </p>

  <p>
    <a href="#screenshots">Screenshots</a> •
    <a href="#features">Features</a> •
    <a href="#requirements">Requirements</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#authentication">Authentication</a> •
    <a href="#uninstalling">Uninstalling</a> •
    <a href="#license">License</a>
  </p>

  <br/>
</div>

---

<a id="screenshots"></a>

## 🖼️ Screenshots

See the plugin in both light and dark mode before you even install it.

<table>
  <tr>
    <td align="center" width="50%">
      <img src="images/light-chat.webp" alt="Light chat view" width="100%">
      <br>
      <strong>Light Chat</strong>
    </td>
    <td align="center" width="50%">
      <img src="images/dark-chat.webp" alt="Dark chat view" width="100%">
      <br>
      <strong>Dark Chat</strong>
    </td>
  </tr>
  <tr>
    <td align="center" width="50%">
      <img src="images/light-settings.webp" alt="Light settings view" width="100%">
      <br>
      <strong>Light Settings</strong>
    </td>
    <td align="center" width="50%">
      <img src="images/dark-settings.webp" alt="Dark settings view" width="100%">
      <br>
      <strong>Dark Settings</strong>
    </td>
  </tr>
</table>

---

<a id="features"></a>

## ✨ Features

- **Dockable panel** — open from **View > IDA Chat** inside IDA
- **AI binary analysis** — ask anything about your binary; Claude responds with code and explanations
- **Automatic script execution** — Claude writes and runs IDA Python scripts against your open binary without any copy-paste
- **Script approval gate** — optional per-request approval before any script runs, with risk classification
- **Context-aware prompts** — cursor position, current function name, and selected text are automatically attached to every message
- **Multi-session workspace** — maintain multiple named conversations per binary; switch, rename, delete, and export from the sidebar
- **Persistent history** — sessions saved to `~/.ida-chat/` scoped per binary, fully resumable across IDA restarts
- **Markdown rendering** — formatted responses with syntax-highlighted code blocks and collapsible long outputs
- **HTML transcript export** — export any session as a single-file HTML transcript with the same visual language as the live chat UI
- **Model selection** — choose between Claude Sonnet, Opus, Opus 1M, and Haiku from the settings panel

---

<a id="requirements"></a>

## 📋 Requirements

| Requirement | Version                                        |
| ----------- | ---------------------------------------------- |
| IDA Pro     | 9.0 or later                                   |
| hcli        | Latest                                         |
| Claude      | API key, OAuth, or system auth via Claude Code |
| Python      | For source checkouts, use the same major.minor version as IDA's embedded Python |

---

<a id="installation"></a>

## 🚀 Installation

Choose one of these two paths:

### Option A: Install the released plugin with `hcli` (recommended)

This is the easiest path if you just want to use the plugin.

1. Install or update [hcli](https://hcli.docs.hex-rays.com/).
2. Install the plugin:

   ```bash
   hcli plugin install https://github.com/tanu360/ida-chat-plugin
   ```

3. Start IDA Pro.
4. Open any binary.
5. Open **View > IDA Chat**.
6. Complete the setup wizard:
   - choose an authentication mode
   - choose the model you want to use
   - save settings

After that, the chat panel is ready to use.

### Option B: Run directly from this source checkout

Use this only if you are developing the plugin or testing local changes.

1. Put this repository at:

   ```text
   ~/.idapro/plugins/ida-chat
   ```

2. Find the Python version used by your IDA build.

   Open IDA and check the startup log, or run this in the IDA Python console:

   ```python
   import sys
   print(f"{sys.version_info.major}.{sys.version_info.minor}")
   ```

   Use that `X.Y` value in the next steps.

3. Create the local environment with the same Python major.minor version:

   ```bash
   uv sync --python X.Y --extra dev
   ```

4. If you do not use `uv`, create the environment manually:

   ```bash
   pythonX.Y -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

5. Start IDA Pro.
6. Open a binary.
7. Open **View > IDA Chat**.
8. Complete the setup wizard on first launch.

Important notes for source checkouts:

- The repo `.venv` must use the same Python major.minor version as your IDA build.
- The plugin loads runtime dependencies from this repo's `.venv` when opened from source.
- If the wrong Python version is used for `.venv`, the plugin may fail to load dependencies inside IDA.

Example:

- if IDA reports Python `3.11`, use `uv sync --python 3.11 --extra dev`
- if IDA reports Python `3.12`, use `uv sync --python 3.12 --extra dev`

The runtime dependencies used by the chat and markdown rendering live in [requirements.txt](requirements.txt).

---

<a id="usage"></a>

## 💡 Usage

1. Open a binary in IDA Pro (any supported format — PE, ELF, Mach-O, etc.)
2. Open **View > IDA Chat** to show the chat panel
3. Complete the setup wizard on first run — takes about 30 seconds
4. Type your question and press **Enter**

### First-Time Setup Wizard

On first launch, the plugin will ask you to choose:

1. An authentication method
2. A model
3. Whether generated scripts should require approval before execution

If you are not sure which auth mode to pick, start with **System** if Claude Code is already working on your machine.

The plugin automatically captures the binary context (current function, cursor address, selection) and passes it to Claude with every message — no manual copy-paste needed.

### Example Prompts

| Goal                    | Prompt                                                    |
| ----------------------- | --------------------------------------------------------- |
| Explore functions       | `"List the main functions in this binary"`                |
| Analyze current address | `"Analyze the function at the current address"`           |
| Find issues             | `"Find potential vulnerabilities in this binary"`         |
| Understand code         | `"Explain what this function does"`                       |
| Clean up disassembly    | `"Rename variables in sub_401000 to be more descriptive"` |
| Cross-references        | `"What calls this function and from where?"`              |

### Keyboard Shortcuts

| Shortcut        | Windows / Linux | macOS         |
| --------------- | --------------- | ------------- |
| Send message    | `Enter`         | `Enter`       |
| New line        | `Shift+Enter`   | `Shift+Enter` |
| Stop generation | `Esc`           | `Esc`         |
| Message history | `↑ / ↓`         | `↑ / ↓`       |

---

<a id="authentication"></a>

## 🔑 Authentication

Three authentication modes are supported, configurable from the setup wizard or settings panel:

| Mode        | Description                                                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------ |
| **System**  | Reuses existing [Claude Code](https://claude.ai/code) credentials — no extra setup needed if you already use Claude Code |
| **API Key** | Anthropic Console API key — get one at [console.anthropic.com](https://console.anthropic.com)                            |
| **OAuth**   | Browser-based login via `claude setup-token`                                                                             |

The System auth mode is recommended if you already have Claude Code installed.

### Which Auth Mode Should You Pick?

- **System**: best default if Claude Code already works on your machine
- **OAuth**: best if you want browser-based sign-in without copying API keys
- **API Key**: best if you prefer explicit Anthropic key-based setup

---

<a id="uninstalling"></a>

## 🗑️ Uninstalling

```bash
hcli plugin uninstall ida-chat
```

---

<a id="license"></a>

## 📜 License

This project is licensed under the [MIT License](LICENSE).

Copyright © 2026 Hex-Rays SA — [support@hex-rays.com](mailto:support@hex-rays.com)
