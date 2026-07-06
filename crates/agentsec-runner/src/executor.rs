use std::time::Instant;

use agentsec_config::target::{HttpRequestSpec, HttpResponseSpec, TargetKind};
use agentsec_config::Target;
use agentsec_scanners::TargetResponse;
use serde_json::Value;

use crate::error::RunnerError;
use crate::jsonpath;

/// Renders `{{ input }}` placeholders in a request body/string against the
/// suite test's `input` text (spec section 11.1 request templating).
fn render_template(template: &str, input: &str) -> String {
    template
        .replace("{{ input }}", input)
        .replace("{{input}}", input)
}

fn render_value(value: &Value, input: &str) -> Value {
    match value {
        Value::String(s) => Value::String(render_template(s, input)),
        Value::Array(items) => Value::Array(items.iter().map(|v| render_value(v, input)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), render_value(v, input)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Executes one suite test's `input` against `target`, returning a
/// normalized `TargetResponse` for scanners to evaluate.
pub async fn execute(
    client: &reqwest::Client,
    target: &Target,
    input: &str,
) -> Result<TargetResponse, RunnerError> {
    match &target.kind {
        TargetKind::HttpChat {
            base_url,
            request,
            response,
            ..
        } => execute_http_chat(client, &target.id, base_url, request, response, input).await,
        TargetKind::OpenaiCompatible {
            base_url,
            api_key_env,
            model,
            organization_env,
            default_system_prompt,
            temperature,
            max_tokens,
        } => {
            execute_openai_compatible(
                client,
                &target.id,
                base_url,
                api_key_env,
                model,
                organization_env.as_deref(),
                default_system_prompt.as_deref(),
                *temperature,
                *max_tokens,
                input,
            )
            .await
        }
        TargetKind::Command { .. } => Err(RunnerError::Runtime(anyhow::anyhow!(
            "command target execution is not yet implemented"
        ))),
        TargetKind::Lab { lab_id } => Err(RunnerError::Runtime(anyhow::anyhow!(
            "lab target \"{lab_id}\" execution is not yet implemented"
        ))),
    }
}

async fn execute_http_chat(
    client: &reqwest::Client,
    target_id: &str,
    base_url: &str,
    request: &HttpRequestSpec,
    response_spec: &HttpResponseSpec,
    input: &str,
) -> Result<TargetResponse, RunnerError> {
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        request.path.trim_start_matches('/')
    );
    let body = render_value(&request.body, input);

    let mut builder = match request.method.to_ascii_uppercase().as_str() {
        "GET" => client.get(&url),
        "PUT" => client.put(&url),
        _ => client.post(&url),
    };
    for (key, value) in &request.headers {
        builder = builder.header(key, render_template(value, input));
    }
    if !matches!(request.method.to_ascii_uppercase().as_str(), "GET") {
        builder = builder.json(&body);
    }

    let started = Instant::now();
    let http_response = builder
        .send()
        .await
        .map_err(|e| RunnerError::TargetUnavailable {
            target_id: target_id.to_string(),
            source: e,
        })?;
    let latency_ms = started.elapsed().as_millis() as u64;

    let status = http_response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(RunnerError::AuthError {
            target_id: target_id.to_string(),
            status: status.as_u16(),
        });
    }

    let raw_json: Value = http_response
        .json()
        .await
        .unwrap_or(Value::String(String::new()));

    build_target_response(target_id, &url, &body, raw_json, response_spec, latency_ms)
}

#[allow(clippy::too_many_arguments)]
async fn execute_openai_compatible(
    client: &reqwest::Client,
    target_id: &str,
    base_url: &str,
    api_key_env: &str,
    model: &str,
    organization_env: Option<&str>,
    default_system_prompt: Option<&str>,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
    input: &str,
) -> Result<TargetResponse, RunnerError> {
    let api_key = std::env::var(api_key_env)
        .map_err(|_| RunnerError::MissingEnvVar(api_key_env.to_string()))?;

    let mut messages = Vec::new();
    if let Some(system_prompt) = default_system_prompt {
        messages.push(serde_json::json!({"role": "system", "content": system_prompt}));
    }
    messages.push(serde_json::json!({"role": "user", "content": input}));

    let mut body = serde_json::json!({
        "model": model,
        "messages": messages,
    });
    if let Some(t) = temperature {
        body["temperature"] = serde_json::json!(t);
    }
    if let Some(mt) = max_tokens {
        body["max_tokens"] = serde_json::json!(mt);
    }

    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let mut builder = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body);

    if let Some(org_env) = organization_env {
        if let Ok(org) = std::env::var(org_env) {
            builder = builder.header("OpenAI-Organization", org);
        }
    }

    let started = Instant::now();
    let http_response = builder
        .send()
        .await
        .map_err(|e| RunnerError::TargetUnavailable {
            target_id: target_id.to_string(),
            source: e,
        })?;
    let latency_ms = started.elapsed().as_millis() as u64;

    let status = http_response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(RunnerError::AuthError {
            target_id: target_id.to_string(),
            status: status.as_u16(),
        });
    }

    let raw_json: Value = http_response
        .json()
        .await
        .unwrap_or(Value::String(String::new()));

    let response_spec = HttpResponseSpec {
        answer_json_path: "$.choices.0.message.content".to_string(),
        citations_json_path: None,
        tool_calls_json_path: None,
        trace_id_json_path: Some("$.id".to_string()),
        retrieved_context_json_path: None,
    };

    build_target_response(target_id, &url, &body, raw_json, &response_spec, latency_ms)
}

fn build_target_response(
    target_id: &str,
    url: &str,
    request_body: &Value,
    raw_json: Value,
    response_spec: &HttpResponseSpec,
    latency_ms: u64,
) -> Result<TargetResponse, RunnerError> {
    let answer =
        jsonpath::extract_string(&raw_json, &response_spec.answer_json_path).ok_or_else(|| {
            RunnerError::ResponseExtraction {
                target_id: target_id.to_string(),
                json_path: response_spec.answer_json_path.clone(),
            }
        })?;

    let citations = response_spec
        .citations_json_path
        .as_deref()
        .map(|p| jsonpath::extract_string_list(&raw_json, p))
        .unwrap_or_default();
    let tool_calls = response_spec
        .tool_calls_json_path
        .as_deref()
        .map(|p| jsonpath::extract_string_list(&raw_json, p))
        .unwrap_or_default();
    let trace_id = response_spec
        .trace_id_json_path
        .as_deref()
        .and_then(|p| jsonpath::extract_string(&raw_json, p));
    let retrieved_context = response_spec
        .retrieved_context_json_path
        .as_deref()
        .and_then(|p| jsonpath::extract_string(&raw_json, p));

    Ok(TargetResponse {
        request_summary: format!("{} {}", url, summarize_json(request_body)),
        answer,
        raw_json: Some(raw_json),
        citations,
        tool_calls,
        trace_id,
        retrieved_context,
        latency_ms,
        task_completed: true,
    })
}

fn summarize_json(value: &Value) -> String {
    let s = value.to_string();
    if s.len() > 200 {
        format!("{}... [truncated]", &s[..200])
    } else {
        s
    }
}
