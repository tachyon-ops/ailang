# MCP Server Configuration Snippets for `ailang`

Add the `ailang-mcp` server to any MCP-compatible coding agent so the agent can
call `ail_stdlib_catalog`, `ail_check_and_prove`, `ail_audit_spec`,
`ail_repair_code`, and `ail_compile_target` natively.

## Claude Code (`.mcp.json` in project root)

```json
{
  "mcpServers": {
    "ailang": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/tachyon-ops/ailang.git",
        "ail",
        "mcp"
      ]
    }
  }
}
```

## Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "ailang": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/tachyon-ops/ailang.git",
        "ail",
        "mcp"
      ]
    }
  }
}
```

## VS Code GitHub Copilot (`.vscode/mcp.json`)

```json
{
  "servers": {
    "ailang": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/tachyon-ops/ailang.git",
        "ail",
        "mcp"
      ]
    }
  }
}
```
