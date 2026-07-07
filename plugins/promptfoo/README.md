# AgentSec ↔ Promptfoo plugin bridge

A reference implementation of a plugin binary speaking AgentSec's
plugin protocol (spec section 21), backed by a real
[Promptfoo](https://www.promptfoo.dev/) redteam run against a local
[Ollama](https://ollama.com/) model. There is no fixture or mock data
anywhere in `agentsec-promptfoo-bridge.js` — every finding it returns
comes from an actual `promptfoo redteam run` fired at a real HTTP
target.

This pairs with `crates/agentsec-integrations/src/promptfoo.rs`, which
implements the AgentSec side of the same protocol and shells out to
whatever binary is named `promptfoo` on `PATH`.

## Requirements

- Docker (recommended), or Node.js 18+ and the `promptfoo` CLI on
  `PATH` directly
- A local [Ollama](https://ollama.com/) install with a chat model
  pulled (the bridge defaults to `gemma4:latest` — see
  `buildPromptfooConfig` in the bridge script to change it)
- A running HTTP target to scan (e.g. `agentsec lab up
  damn-vulnerable-ai-agent`, or any `http-chat` target from your own
  `agentsec.yml`)

## Build

```bash
cd plugins/promptfoo
docker build -t agentsec-promptfoo-bridge .
```

## Run

The bridge speaks three subcommands, per spec 21.2–21.4:

```bash
# capabilities
docker run --rm agentsec-promptfoo-bridge capabilities

# version
docker run --rm agentsec-promptfoo-bridge version

# scan (reads a spec-21.3 input file, writes a spec-21.4 output file)
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/scan-work:/work/scan-work" \
  agentsec-promptfoo-bridge scan \
  --input /work/scan-work/input.json \
  --output /work/scan-work/output.json
```

Example `input.json` (targets a local http-chat endpoint on port
7002 — adjust `base_url` to your actual target):

```json
{
  "run_id": "run_smoketest_001",
  "target": {
    "id": "helperbot",
    "type": "http-chat",
    "base_url": "http://host.docker.internal:7002"
  },
  "suite": {
    "id": "prompt-injection-basic"
  },
  "options": {
    "timeout_seconds": 180
  }
}
```

## Wiring it into `agentsec`

Put the built binary (or a wrapper script that calls the Docker image)
on `PATH` as `promptfoo`, then:

```bash
agentsec plugin list
agentsec plugin info promptfoo
agentsec plugin run promptfoo --target helperbot --suite prompt-injection-basic
```

## Notes

- `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true` is set in the
  Dockerfile so probe generation and grading stay fully local — no
  calls to Promptfoo's cloud service.
- `promptfoo redteam run` exits with status `100` when it finds at
  least one failing (i.e. vulnerable) test case. The bridge treats that
  as a normal outcome, not an error, and continues on to read the
  output file.
