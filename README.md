# Sentinel MCP - AI Security Proxy

Sentinel is a standalone Model Context Protocol (MCP) server that provides a tiered "Waterfall Defense" for AI agents.

## Project Structure

- `main.py`: MCP Server entry point.
- `sentinel/`: Core logic package.
    - `defense.py`: Waterfall Defense orchestration (Cache -> Tiny Guard -> Expert Audit).
    - `constitutions/`: **NEW!** Add or or edit `.md` files here to define safety rules.
    - `models.py`: Gemini API client (supports direct and Vertex AI).
- `tests/`: Comprehensive test suite for all layers.

## For Developers: Adding Constitutions

To add a new safety domain (e.g., 'healthcare'):
1. Create `sentinel/constitutions/healthcare.md`.
2. Write your safety rules in plain text/markdown.
3. Use the `check_safety` tool with `constitution="healthcare"`.
   - The server dynamically loads new files—no restart or code changes required!

## Installation & Usage

1. **Setup Environment**:
   ```bash
   export GOOGLE_API_KEY="your-key"
   # Or for Vertex AI
   export GOOGLE_GENAI_USE_VERTEXAI=True
   export GOOGLE_CLOUD_PROJECT="your-project"
   ```

2. **Run Server Local**:
   ```bash
   python main.py
   ```

3. **Run Tests**:
   ```bash
   # From the root directory
   python tests/test_sentinel_mcp.py
   ```
      }
    }
  }
}
