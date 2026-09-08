# Local Ollama example

Real config for running AgentSec against a local Ollama server, validated
live (not a mock) against `gemma4:latest` on Ollama 0.20.3.

## Prerequisites

```bash
ollama pull gemma4          # or any OpenAI-compatible chat model
ollama serve                # if not already running
```

## Usage

```bash
cd examples/ollama-local

agentsec ci --config agentsec.yml
agentsec scan --target ollama-gemma4 --suite prompt-injection-basic --config agentsec.yml
agentsec experiment run experiment-gemma4.yml --config agentsec.yml
agentsec attack --target ollama-gemma4 --suite prompt-injection-basic --mutators all --config agentsec.yml
```

No `AGENTSEC_API_KEY` (or any env var) is required — `api_key_env` is
optional on `openai-compatible` targets and is simply omitted here.
Ollama's cold-start latency for the first call can be ~30-50s; subsequent
calls with a warm model are typically under 10s for a 4-test suite.

To point at a different local model, change `model:` in `agentsec.yml`
to any tag from `ollama list`.
