# Sentinel MCP Server

An independent Model Context Protocol (MCP) server for the Sentinel-OSS security framework.

## Features
- **Waterfall Defense Tool**: Multilayered safety auditing (Cache -> Tiny Guard -> Expert Audit).
- **Red Team Attack Generator**: Tool for generating sophisticated adversarial prompts.
- **Safety Resources**: Direct access to the Banking Safety Constitution.

## Installation

```bash
pip install mcp fastmcp google-genai python-dotenv
```

## Configuration

Set your Gemini API key in your environment or a `.env` file:
```bash
GOOGLE_API_KEY=your_api_key_here
```

## Usage

Run the server with:
```bash
python main.py
```

To use in your IDE (Windsurf/Cursor), add it to your `config.json`:
```json
{
  "mcpServers": {
    "sentinel": {
      "command": "python",
      "args": ["/path/to/sentinel-mcp/main.py"],
      "env": {
        "GOOGLE_API_KEY": "your_api_key"
      }
    }
  }
}
```
