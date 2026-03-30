//! Server-Sent Events (SSE) parser for LLM streaming responses.
//!
//! LLM providers return streaming responses as SSE event streams. This module
//! parses the event stream format and extracts token usage data from the
//! provider-specific event payloads.
//!
//! # Provider formats
//!
//! **`OpenAI`**: Usage in the final data chunk (before `[DONE]`) when
//! `stream_options: {"include_usage": true}` is set. The chunk has a `usage`
//! object with `prompt_tokens` and `completion_tokens`.
//!
//! **Anthropic**: Usage split across events — `input_tokens` in
//! `message_start`, `output_tokens` in `message_delta` (with `usage` field).
//!
//! **Google**: `usageMetadata` present in each chunk; the last chunk has
//! the final cumulative counts.

use sanctum_budget::UsageData;

/// A parsed SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Optional event type (from `event:` field). `None` for unnamed events.
    pub event_type: Option<String>,
    /// The data payload (from `data:` field). May span multiple `data:` lines
    /// concatenated with newlines per the SSE spec.
    pub data: String,
}

/// Parse an SSE event stream body into individual events.
///
/// Per the SSE specification:
/// - Lines starting with `data:` contain event data
/// - Lines starting with `event:` set the event type
/// - Blank lines terminate an event
/// - Lines starting with `:` are comments (ignored)
/// - The special payload `[DONE]` signals end-of-stream (`OpenAI` convention)
pub fn parse_sse_events(body: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut current_event_type: Option<String> = None;
    let mut current_data_lines: Vec<&str> = Vec::new();

    for line in body.lines() {
        if line.is_empty() {
            // Blank line = event boundary
            if !current_data_lines.is_empty() {
                let data = current_data_lines.join("\n");
                events.push(SseEvent {
                    event_type: current_event_type.take(),
                    data,
                });
                current_data_lines.clear();
            }
            current_event_type = None;
            continue;
        }

        // Comment lines — ignore
        if line.starts_with(':') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("event:") {
            current_event_type = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("data:") {
            // SSE spec: strip exactly one leading space after the colon
            current_data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
        // Other fields (id:, retry:) are ignored for our purposes
    }

    // Flush any trailing event without a final blank line
    if !current_data_lines.is_empty() {
        let data = current_data_lines.join("\n");
        events.push(SseEvent {
            event_type: current_event_type.take(),
            data,
        });
    }

    events
}

/// Extract token usage data from a sequence of SSE events.
///
/// Tries provider-specific extraction in order:
/// 1. Anthropic — accumulates `input_tokens` from `message_start` and
///    `output_tokens` from `message_delta`.
/// 2. Google — takes the last chunk's `usageMetadata`.
/// 3. `OpenAI` — takes the last chunk's `usage` object (non-null).
///
/// Returns `None` if no usage data can be extracted.
pub fn extract_usage_from_events(events: &[SseEvent]) -> Option<UsageData> {
    // Try Anthropic first (has distinctive event types)
    if let Some(usage) = try_anthropic_sse(events) {
        return Some(usage);
    }

    // Try Google (has usageMetadata)
    if let Some(usage) = try_google_sse(events) {
        return Some(usage);
    }

    // Try OpenAI (usage in final chunk)
    try_openai_sse(events)
}

/// Extract usage from OpenAI-format SSE events.
///
/// `OpenAI` includes usage in the final data chunk before `[DONE]` when
/// `stream_options.include_usage` is set. The chunk looks like:
/// ```json
/// {"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":50}}
/// ```
fn try_openai_sse(events: &[SseEvent]) -> Option<UsageData> {
    // Walk events in reverse to find the last chunk with non-null usage.
    // Use match/continue (not `?`) to avoid returning None from the function
    // when a single chunk fails to parse — we want to keep searching.
    for event in events.iter().rev() {
        if event.data == "[DONE]" {
            continue;
        }

        let json: serde_json::Value = match serde_json::from_str(&event.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let Some(obj) = json.as_object() else {
            continue;
        };

        // Must have a `usage` field that is non-null
        let usage = match obj.get("usage") {
            Some(u) if !u.is_null() => u,
            _ => continue,
        };

        let model = obj
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let Some(input_tokens) = usage
            .get("prompt_tokens")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let Some(output_tokens) = usage
            .get("completion_tokens")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };

        return Some(UsageData {
            provider: sanctum_budget::Provider::OpenAI,
            model,
            input_tokens,
            output_tokens,
        });
    }

    None
}

/// Extract usage from Anthropic-format SSE events.
///
/// Anthropic splits usage across two events:
/// - `message_start`: contains `message.usage.input_tokens`
/// - `message_delta`: contains `usage.output_tokens`
fn try_anthropic_sse(events: &[SseEvent]) -> Option<UsageData> {
    let mut input_tokens: Option<u64> = None;
    let mut output_tokens: Option<u64> = None;
    let mut model: Option<String> = None;

    for event in events {
        let json: serde_json::Value = match serde_json::from_str(&event.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event_type = json
            .get("type")
            .and_then(serde_json::Value::as_str)
            .or(event.event_type.as_deref());

        match event_type {
            Some("message_start") => {
                if let Some(msg) = json.get("message") {
                    if model.is_none() {
                        model = msg
                            .get("model")
                            .and_then(serde_json::Value::as_str)
                            .map(String::from);
                    }
                    if let Some(usage) = msg.get("usage") {
                        input_tokens = usage
                            .get("input_tokens")
                            .and_then(serde_json::Value::as_u64);
                    }
                }
            }
            Some("message_delta") => {
                if let Some(usage) = json.get("usage") {
                    output_tokens = usage
                        .get("output_tokens")
                        .and_then(serde_json::Value::as_u64);
                }
            }
            _ => {}
        }
    }

    let input = input_tokens?;
    let output = output_tokens?;

    Some(UsageData {
        provider: sanctum_budget::Provider::Anthropic,
        model: model.unwrap_or_else(|| "unknown".to_string()),
        input_tokens: input,
        output_tokens: output,
    })
}

/// Extract usage from Google Gemini-format SSE events.
///
/// Google includes `usageMetadata` in each streaming chunk. The last chunk
/// contains the cumulative final counts.
fn try_google_sse(events: &[SseEvent]) -> Option<UsageData> {
    // Walk events in reverse to find the last chunk with usageMetadata.
    // Use match/continue (not `?`) to avoid returning None from the function
    // when a single chunk fails to parse — we want to keep searching.
    for event in events.iter().rev() {
        let json: serde_json::Value = match serde_json::from_str(&event.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let Some(obj) = json.as_object() else {
            continue;
        };

        let Some(usage_metadata) = obj.get("usageMetadata") else {
            continue;
        };

        let model = obj
            .get("modelVersion")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let Some(input_tokens) = usage_metadata
            .get("promptTokenCount")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let Some(output_tokens) = usage_metadata
            .get("candidatesTokenCount")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };

        return Some(UsageData {
            provider: sanctum_budget::Provider::Google,
            model,
            input_tokens,
            output_tokens,
        });
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_budget::Provider;

    // ---- SSE parser tests ----

    #[test]
    fn parse_empty_body() {
        let events = parse_sse_events("");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_data_event() {
        let body = "data: hello world\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello world");
        assert_eq!(events[0].event_type, None);
    }

    #[test]
    fn parse_event_with_type() {
        let body = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_deref(), Some("message_start"));
        assert_eq!(events[0].data, "{\"type\":\"message_start\"}");
    }

    #[test]
    fn parse_multiple_events() {
        let body = "data: first\n\ndata: second\n\ndata: third\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].data, "first");
        assert_eq!(events[1].data, "second");
        assert_eq!(events[2].data, "third");
    }

    #[test]
    fn parse_multi_line_data() {
        let body = "data: line1\ndata: line2\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line1\nline2");
    }

    #[test]
    fn parse_comments_ignored() {
        let body = ": this is a comment\ndata: hello\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn parse_done_event() {
        let body = "data: {\"content\":\"hi\"}\n\ndata: [DONE]\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].data, "[DONE]");
    }

    #[test]
    fn parse_trailing_event_without_blank_line() {
        let body = "data: trailing";
        let events = parse_sse_events(body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "trailing");
    }

    #[test]
    fn parse_data_with_leading_space() {
        // SSE spec: single leading space after colon is stripped
        let body = "data: hello\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn parse_data_without_space_after_colon() {
        let body = "data:no-space\n\n";
        let events = parse_sse_events(body);
        assert_eq!(events[0].data, "no-space");
    }

    // ---- OpenAI SSE usage extraction ----

    #[test]
    fn openai_sse_with_usage_in_final_chunk() {
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{}}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50,\"total_tokens\":150}}\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_some());
        let usage = usage.unwrap();
        assert_eq!(usage.provider, Provider::OpenAI);
        assert_eq!(usage.model, "gpt-4o");
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn openai_sse_without_usage_returns_none() {
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_none());
    }

    #[test]
    fn openai_sse_usage_in_middle_chunk_still_found() {
        // Edge case: usage appears in a non-final chunk (unusual but should still work)
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":200,\"completion_tokens\":100,\"total_tokens\":300}}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":null}\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        // Should still find it by walking backwards past null-usage chunks
        assert!(usage.is_some());
        let usage = usage.unwrap();
        assert_eq!(usage.input_tokens, 200);
        assert_eq!(usage.output_tokens, 100);
    }

    // ---- Anthropic SSE usage extraction ----

    #[test]
    fn anthropic_sse_extracts_split_usage() {
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6-20260320\",\"usage\":{\"input_tokens\":200,\"output_tokens\":0}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":100}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_some());
        let usage = usage.unwrap();
        assert_eq!(usage.provider, Provider::Anthropic);
        assert_eq!(usage.model, "claude-sonnet-4-6-20260320");
        assert_eq!(usage.input_tokens, 200);
        assert_eq!(usage.output_tokens, 100);
    }

    #[test]
    fn anthropic_sse_missing_message_delta_returns_none() {
        // Only message_start, no message_delta with output_tokens
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6-20260320\",\"usage\":{\"input_tokens\":200,\"output_tokens\":0}}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_none());
    }

    // ---- Google SSE usage extraction ----

    #[test]
    fn google_sse_extracts_from_last_chunk() {
        let body = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hi\"}]}}],\"modelVersion\":\"gemini-2.5-pro\",\"usageMetadata\":{\"promptTokenCount\":300,\"candidatesTokenCount\":50}}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" there\"}]}}],\"modelVersion\":\"gemini-2.5-pro\",\"usageMetadata\":{\"promptTokenCount\":300,\"candidatesTokenCount\":150}}\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_some());
        let usage = usage.unwrap();
        assert_eq!(usage.provider, Provider::Google);
        assert_eq!(usage.model, "gemini-2.5-pro");
        assert_eq!(usage.input_tokens, 300);
        assert_eq!(usage.output_tokens, 150);
    }

    #[test]
    fn google_sse_single_chunk() {
        let body = "data: {\"modelVersion\":\"gemini-2.5-flash\",\"usageMetadata\":{\"promptTokenCount\":50,\"candidatesTokenCount\":25}}\n\n";
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_some());
        let usage = usage.unwrap();
        assert_eq!(usage.provider, Provider::Google);
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 25);
    }

    // ---- Edge cases ----

    #[test]
    fn empty_events_returns_none() {
        let usage = extract_usage_from_events(&[]);
        assert!(usage.is_none());
    }

    #[test]
    fn non_json_events_returns_none() {
        let events = vec![SseEvent {
            event_type: None,
            data: "not json at all".to_string(),
        }];
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_none());
    }

    #[test]
    fn done_only_returns_none() {
        let events = vec![SseEvent {
            event_type: None,
            data: "[DONE]".to_string(),
        }];
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_none());
    }

    #[test]
    fn malformed_json_in_stream_skipped_gracefully() {
        let body = concat!(
            "data: {bad json}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = extract_usage_from_events(&events);
        assert!(usage.is_some());
        let usage = usage.unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    // ---- Regression: malformed JSON AFTER valid usage must not abort extraction ----

    #[test]
    fn openai_malformed_json_after_usage_still_extracts() {
        // The valid usage chunk appears BEFORE the malformed chunk in stream order.
        // Reverse iteration hits the malformed chunk first — must continue, not abort.
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":17,\"total_tokens\":59}}\n\n",
            "data: {truncated response\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = try_openai_sse(&events);
        assert!(
            usage.is_some(),
            "must find usage despite later malformed chunk"
        );
        let usage = usage.unwrap();
        assert_eq!(usage.input_tokens, 42);
        assert_eq!(usage.output_tokens, 17);
    }

    #[test]
    fn openai_chunks_without_usage_key_skipped() {
        // When stream_options.include_usage is not set, chunks lack the usage key entirely.
        // The extractor must continue past these, not abort.
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = try_openai_sse(&events);
        assert!(usage.is_none(), "no usage data should be found");
    }

    #[test]
    fn openai_empty_usage_object_skipped() {
        // usage: {} with no prompt_tokens/completion_tokens
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{}}\n\n",
            "data: [DONE]\n\n"
        );
        let events = parse_sse_events(body);
        let usage = try_openai_sse(&events);
        assert!(
            usage.is_none(),
            "empty usage object should not produce data"
        );
    }

    #[test]
    fn google_malformed_json_after_usage_still_extracts() {
        let body = concat!(
            "data: {\"modelVersion\":\"gemini-2.5-pro\",\"usageMetadata\":{\"promptTokenCount\":100,\"candidatesTokenCount\":50}}\n\n",
            "data: {truncated\n\n"
        );
        let events = parse_sse_events(body);
        let usage = try_google_sse(&events);
        assert!(
            usage.is_some(),
            "must find usage despite later malformed chunk"
        );
        let usage = usage.unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn google_chunk_without_usage_metadata_skipped() {
        // A chunk that is valid JSON but lacks usageMetadata
        let body = concat!(
            "data: {\"modelVersion\":\"gemini-2.5-pro\",\"usageMetadata\":{\"promptTokenCount\":100,\"candidatesTokenCount\":50}}\n\n",
            "data: {\"modelVersion\":\"gemini-2.5-pro\",\"candidates\":[]}\n\n"
        );
        let events = parse_sse_events(body);
        let usage = try_google_sse(&events);
        assert!(
            usage.is_some(),
            "must skip chunk without usageMetadata and find earlier one"
        );
        let usage = usage.unwrap();
        assert_eq!(usage.input_tokens, 100);
    }

    // ---- SSE spec: single leading space stripped ----

    #[test]
    fn parse_data_preserves_extra_leading_spaces() {
        // SSE spec: only ONE leading space after colon is stripped
        let body = "data:   three spaces\n\n";
        let events = parse_sse_events(body);
        assert_eq!(
            events[0].data, "  three spaces",
            "must preserve extra spaces"
        );
    }
}
