"""
AI Validator — BedrockPromptHandler (direct Converse + application-owned tools).

Recovery architecture (Amazon Bedrock Agents Classic is closed to new
customers; CreateAgent is unavailable in the destination account). This handler
replaces the legacy Bedrock Agent orchestration with a direct
`bedrock-runtime` Converse call plus an application-owned tool-use loop that
dispatches to the existing Processor Lambda.

Runtime path:
  API Gateway (HTTP API) event
    -> extract prompt
    -> bedrock-runtime Converse (with system instruction + toolConfig)
    -> optional model toolUse
        -> validate tool name against an explicit allowlist
        -> invoke Processor Lambda synchronously (RequestResponse)
        -> return the tool result to Converse as a toolResult
    -> final model text
    -> HTTP 200 {"response": "..."}

Frozen destination decisions preserved:
  - Authentication is owned by the API Gateway JWT authorizer. This handler
    does NOT verify or decode JWTs.
  - No CloudFront signed-URL feature, no SSM keys, no source account / Cognito /
    CloudFront values.
  - Response contract preserved: 200 {"response": <string>}.

Bedrock usage:
  - client: boto3.client("bedrock-runtime")
  - API: Converse (synchronous) on the cross-region inference profile
    (BEDROCK_INFERENCE_PROFILE_ID). No bedrock-agent-runtime, no invoke_agent,
    no agentId/agentAliasId.

Tool dispatch security:
  - Explicit allowlist maps a fixed set of tool names to exactly one Processor
    operation each. Unknown tool names are rejected.
  - Bounded tool-use loop (MAX_TOOL_ROUNDS) prevents unbounded recursion.
  - PromptHandler never lets the model choose an arbitrary Lambda or operation.

Runtime: python3.12, boto3 provided by the Lambda runtime (no third-party deps).
The system instruction ships in the deployment ZIP as instruction.txt at the
archive root (see scripts/build_lambdas.py).
"""

import json
import os

import boto3
from botocore.exceptions import ClientError

_ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://ai.usmissionhero.com")

# CORS: API Gateway owns CORS for the HTTP API. These headers are a minimal
# fallback so direct/proxy responses remain browser-usable; they intentionally
# reference the destination application origin only.
_CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": _ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
}

# Maximum number of model<->tool round trips per request. Conservative bound to
# prevent unbounded model/tool recursion.
MAX_TOOL_ROUNDS = 5

# Hard ceiling on the TOTAL number of Processor Lambda invocations per incoming
# API request. This is independent of MAX_TOOL_ROUNDS and of the number of
# toolUse blocks the model returns in a single Converse response. The sixth
# Processor invocation must never execute.
MAX_TOOL_INVOCATIONS = 5

# Explicit, immutable allowlist: model tool name -> Processor "operation".
# The model can ONLY ever cause these four Processor operations to run. Any
# other tool name is rejected before any Lambda invocation.
_TOOL_TO_OPERATION = {
    "scanFile": "scanFile",
    "transferFile": "transferFile",
    "getClassificationReport": "getClassificationReport",
    "scanBucket": "scanBucket",
}


class ConfigurationError(Exception):
    """Raised when required runtime configuration is missing."""


class ToolDispatchError(Exception):
    """Raised when a tool request is invalid or the Processor fails."""


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(f"Missing required environment variable: {name}")
    return value


def _load_system_instruction():
    """Load the reviewed system instruction packaged alongside this handler.

    The build system places instruction.txt at the ZIP root. The reviewed
    instruction is part of the AI Validator's security/behavior contract, so
    this FAILS CLOSED: if instruction.txt is missing, unreadable, empty, or
    whitespace-only, raise ConfigurationError (no generic fallback). The caller
    surfaces this as a generic 500 without leaking the path/exception, and
    Converse is never invoked without the reviewed instruction.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "instruction.txt")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read().strip()
    except OSError as exc:
        raise ConfigurationError("system instruction is not available") from exc
    if not text:
        raise ConfigurationError("system instruction is empty")
    return text


def _tool_config():
    """Converse toolConfig derived from the Processor's operation contracts."""
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": "scanFile",
                    "description": (
                        "Scan a single S3 object for PII/PHI/FedRAMP issues and "
                        "return its data classification (Type1/Type2/Type3)."
                    ),
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "bucketName": {"type": "string", "description": "S3 bucket containing the object."},
                                "objectKey": {"type": "string", "description": "Key of the object to scan."},
                            },
                            "required": ["bucketName", "objectKey"],
                        }
                    },
                }
            },
            {
                "toolSpec": {
                    "name": "transferFile",
                    "description": (
                        "Scan then transfer an S3 object from a source bucket to a "
                        "destination bucket; blocks transfer for Type3 data."
                    ),
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "sourceBucket": {"type": "string"},
                                "sourceKey": {"type": "string"},
                                "destinationBucket": {"type": "string"},
                                "destinationKey": {"type": "string", "description": "Optional; defaults to sourceKey."},
                            },
                            "required": ["sourceBucket", "sourceKey", "destinationBucket"],
                        }
                    },
                }
            },
            {
                "toolSpec": {
                    "name": "getClassificationReport",
                    "description": "Retrieve a previously stored classification report by scanId.",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "scanId": {"type": "string", "description": "Identifier of a prior scan."},
                            },
                            "required": ["scanId"],
                        }
                    },
                }
            },
            {
                "toolSpec": {
                    "name": "scanBucket",
                    "description": "Scan objects in an S3 bucket (optionally under a prefix) for PII/PHI/FedRAMP issues.",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "bucketName": {"type": "string"},
                                "prefix": {"type": "string", "description": "Optional key prefix to narrow the scan."},
                                "maxKeys": {"type": "integer", "description": "Optional max objects to scan."},
                            },
                            "required": ["bucketName"],
                        }
                    },
                }
            },
        ]
    }


def _get_request(event):
    """Return (method, body_str) for HTTP API v2 or REST v1 proxy events."""
    event = event or {}
    request_context = event.get("requestContext") or {}
    if "http" in request_context:  # HTTP API v2
        method = (request_context.get("http") or {}).get("method", "")
        body = event.get("body")
        if event.get("isBase64Encoded") and body:
            import base64

            body = base64.b64decode(body).decode("utf-8", errors="replace")
        return method, body
    # REST API v1 proxy
    return event.get("httpMethod", ""), event.get("body")


def _response(status_code, payload):
    return {
        "statusCode": status_code,
        "headers": _CORS_HEADERS,
        "body": json.dumps(payload),
    }


def _error(message, status_code=500):
    return _response(status_code, {"error": message})


def _invoke_processor(operation, tool_input):
    """Invoke the Processor Lambda synchronously using its direct-dispatch
    contract: {"operation": <op>, ...args}. Returns a JSON-serializable result
    dict to hand back to the model. Raises ToolDispatchError on any failure.
    """
    function_name = _require_env("PROCESSOR_FUNCTION_NAME")
    payload = {"operation": operation}
    if isinstance(tool_input, dict):
        # Only pass through the arguments the Processor operations understand.
        for key in ("bucketName", "objectKey", "sourceBucket", "sourceKey",
                    "destinationBucket", "destinationKey", "scanId", "prefix", "maxKeys"):
            if key in tool_input and tool_input[key] is not None:
                payload[key] = tool_input[key]

    client = boto3.client("lambda")
    try:
        resp = client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        print(f"Processor invoke ClientError: {code}")
        raise ToolDispatchError("processor invocation failed") from exc

    if resp.get("FunctionError"):
        print(f"Processor FunctionError: {resp.get('FunctionError')}")
        raise ToolDispatchError("processor returned a function error")

    raw = resp.get("Payload")
    if raw is None:
        raise ToolDispatchError("processor returned no payload")
    try:
        body = raw.read() if hasattr(raw, "read") else raw
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", errors="replace")
        result = json.loads(body) if body else {}
    except (ValueError, TypeError) as exc:
        raise ToolDispatchError("processor returned a non-JSON payload") from exc

    # Normalize the Processor's Bedrock-envelope response to the inner
    # application/json body when present; otherwise return the raw result.
    if isinstance(result, dict):
        inner = (
            result.get("response", {})
            .get("responseBody", {})
            .get("application/json")
            if isinstance(result.get("response"), dict)
            else None
        )
        if inner is not None:
            return inner
    return result


def _extract_tool_uses(message):
    """Return the list of toolUse content blocks in an assistant message."""
    uses = []
    for block in (message or {}).get("content", []) or []:
        if isinstance(block, dict) and "toolUse" in block:
            uses.append(block["toolUse"])
    return uses


def _extract_text(message):
    """Concatenate text blocks from an assistant message safely."""
    parts = []
    for block in (message or {}).get("content", []) or []:
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "".join(parts).strip()


def run_converse(prompt, model_id):
    """Drive a bounded Converse tool-use loop and return the final text.

    Two independent hard bounds protect against runaway tool use:
      - MAX_TOOL_ROUNDS caps the number of Converse round trips.
      - MAX_TOOL_INVOCATIONS caps the TOTAL number of Processor invocations for
        this request, regardless of how many toolUse blocks a single response
        contains. Fail-closed: if honoring a response would require exceeding
        the remaining invocation budget, the tool-dispatch cycle is rejected
        BEFORE any excess Processor call runs (the sixth call never executes).
    """
    client = boto3.client("bedrock-runtime")
    # Fail closed on the reviewed instruction before any model call.
    system = [{"text": _load_system_instruction()}]
    tool_config = _tool_config()
    messages = [{"role": "user", "content": [{"text": prompt}]}]

    invocations_used = 0

    for _ in range(MAX_TOOL_ROUNDS + 1):
        response = client.converse(
            modelId=model_id,
            system=system,
            messages=messages,
            toolConfig=tool_config,
        )
        output_message = (response.get("output") or {}).get("message") or {}
        messages.append(output_message)
        stop_reason = response.get("stopReason")

        if stop_reason != "tool_use":
            text = _extract_text(output_message)
            return text or "No response generated."

        tool_uses = _extract_tool_uses(output_message)

        # Count only tool uses that would actually invoke the Processor (i.e.
        # allowlisted tools). Unknown tools never call the Processor.
        would_invoke = sum(1 for tu in tool_uses if _TOOL_TO_OPERATION.get(tu.get("name")) is not None)
        if invocations_used + would_invoke > MAX_TOOL_INVOCATIONS:
            # Reject the whole cycle before executing any excess call. This
            # guarantees Processor calls/request <= MAX_TOOL_INVOCATIONS.
            raise ToolDispatchError("total tool-invocation budget exceeded")

        tool_results = []
        for tool_use in tool_uses:
            tool_name = tool_use.get("name")
            tool_use_id = tool_use.get("toolUseId")
            operation = _TOOL_TO_OPERATION.get(tool_name)
            if operation is None:
                # Reject unknown tool safely; report back to the model as error.
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"text": "Unknown or unsupported tool."}],
                        "status": "error",
                    }
                })
                continue
            # Defensive: never exceed the ceiling even if counting logic drifts.
            if invocations_used >= MAX_TOOL_INVOCATIONS:
                raise ToolDispatchError("total tool-invocation budget exceeded")
            invocations_used += 1
            try:
                result = _invoke_processor(operation, tool_use.get("input") or {})
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"json": result}],
                        "status": "success",
                    }
                })
            except ToolDispatchError:
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"text": "The requested operation could not be completed."}],
                        "status": "error",
                    }
                })

        messages.append({"role": "user", "content": tool_results})

    # Exceeded the allowed number of tool rounds.
    raise ToolDispatchError("tool-use loop exceeded the maximum number of rounds")


def lambda_handler(event, context=None):
    try:
        model_id = _require_env("BEDROCK_INFERENCE_PROFILE_ID")
        # PROCESSOR_FUNCTION_NAME is validated lazily when a tool is used.
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return _error("Service is not correctly configured.", 500)

    method, raw_body = _get_request(event)

    # CORS preflight (API Gateway normally handles this; safe fallback).
    if str(method).upper() == "OPTIONS":
        return {"statusCode": 204, "headers": _CORS_HEADERS, "body": ""}

    # Authentication is enforced by the API Gateway JWT authorizer upstream.
    try:
        body_json = json.loads(raw_body or "{}")
    except (ValueError, TypeError):
        return _error("Invalid JSON in request body.", 400)

    prompt = (body_json.get("prompt") or "").strip()
    if not prompt:
        return _error("Missing 'prompt' parameter in the request body.", 400)

    try:
        response_text = run_converse(prompt, model_id)
    except ConfigurationError as exc:
        # A tool was requested but PROCESSOR_FUNCTION_NAME is not configured.
        print(f"Configuration error during tool dispatch: {exc}")
        return _error("Service is not correctly configured.", 500)
    except ToolDispatchError as exc:
        print(f"Tool dispatch error: {exc}")
        return _error("The AI service could not complete the requested operation.", 502)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        print(f"Bedrock ClientError: {code}")
        return _error("Upstream AI service error.", 502)
    except Exception as exc:  # noqa: BLE001 - final safety net, sanitized to client
        print(f"Unhandled error: {exc}")
        return _error("Internal error.", 500)

    return _response(200, {"response": response_text})
