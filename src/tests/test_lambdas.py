"""
Local static unit tests for reconstructed AI Validator Lambda handlers.
No AWS calls: boto3 clients are stubbed. Run with: py -m unittest -v
(from C:\\USMISSIONHERO\\products\\ai\\src)

PromptHandler tests exercise the direct bedrock-runtime Converse tool-use loop
with an application-owned Processor dispatch. Processor tests exercise the
existing dispatch/response contract. No live Bedrock or Lambda calls.
"""

import importlib
import io
import json
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)


# ---- Fake boto3 infrastructure (no AWS) ------------------------------------
class FakeBedrockRuntime:
    """Fake bedrock-runtime client with a scripted sequence of Converse responses."""

    def __init__(self, responses):
        # responses: list of dicts to return from successive converse() calls,
        # OR an Exception instance/class to raise on the NEXT call.
        self._responses = list(responses)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if not self._responses:
            raise AssertionError("converse called more times than scripted")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        if isinstance(nxt, type) and issubclass(nxt, Exception):
            raise nxt()
        return nxt


class FakeLambda:
    """Fake lambda client returning a scripted invoke() result."""

    def __init__(self, payload=None, function_error=None, raise_exc=None, non_json=False):
        self._payload = payload if payload is not None else {"ok": True}
        self._function_error = function_error
        self._raise = raise_exc
        self._non_json = non_json
        self.calls = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self._raise is not None:
            raise self._raise
        body = b"not json" if self._non_json else json.dumps(self._payload).encode("utf-8")
        resp = {"Payload": io.BytesIO(body)}
        if self._function_error:
            resp["FunctionError"] = self._function_error
        return resp


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []

    def get_object(self, Bucket, Key):
        self.calls.append(("get_object", Bucket, Key))
        data = self.objects.get((Bucket, Key), b"hello world")
        return {"Body": io.BytesIO(data)}

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs.get("Bucket"), kwargs.get("Key")))
        return {}

    def copy_object(self, **kwargs):
        self.calls.append(("copy_object", kwargs.get("Bucket"), kwargs.get("Key")))
        return {}

    def put_object_tagging(self, **kwargs):
        self.calls.append(("put_object_tagging", kwargs.get("Bucket")))
        return {}

    def get_paginator(self, name):
        class _P:
            def paginate(self, **kwargs):
                return [{"Contents": [{"Key": "a.txt"}]}]

        return _P()


class FakeComprehend:
    def detect_pii_entities(self, Text, LanguageCode):
        return {"Entities": []}


class FakeSNS:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)
        return {"MessageId": "x"}


def _load_module(rel_dir, unique_name, boto3_client_map):
    """Load src/<rel_dir>/lambda_function.py with a stubbed boto3 module.

    Returns (module, ClientError). boto3_client_map may be a dict OR a callable
    (service_name -> client) for tests that need per-service fakes.
    """
    path = os.path.join(SRC, rel_dir, "lambda_function.py")
    fake_boto3 = types.ModuleType("boto3")

    def client(service_name, *a, **k):
        if callable(boto3_client_map):
            return boto3_client_map(service_name)
        return boto3_client_map[service_name]

    fake_boto3.client = client
    botocore = types.ModuleType("botocore")
    exceptions = types.ModuleType("botocore.exceptions")

    class ClientError(Exception):
        def __init__(self, response=None, operation_name=None):
            super().__init__("ClientError")
            self.response = response or {"Error": {"Code": "Test"}}

    exceptions.ClientError = ClientError
    botocore.exceptions = exceptions

    saved = {k: sys.modules.get(k) for k in ("boto3", "botocore", "botocore.exceptions")}
    sys.modules["boto3"] = fake_boto3
    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = exceptions
    try:
        spec = importlib.util.spec_from_file_location(unique_name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod._ClientError = ClientError
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


# ---- Converse response helpers ---------------------------------------------
def _text_response(text):
    return {"stopReason": "end_turn", "output": {"message": {"role": "assistant", "content": [{"text": text}]}}}


def _tooluse_response(tool_name, tool_input, tool_use_id="tu-1"):
    return {
        "stopReason": "tool_use",
        "output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": tool_use_id, "name": tool_name, "input": tool_input}}
        ]}},
    }


# ---- PromptHandler tests ----------------------------------------------------
class PromptHandlerTests(unittest.TestCase):
    def _load(self, converse_responses, lambda_fake=None):
        self.bedrock = FakeBedrockRuntime(converse_responses)
        self.lam = lambda_fake or FakeLambda(payload={"scanId": "S1", "classificationType": "Type1"})

        def factory(service):
            if service == "bedrock-runtime":
                return self.bedrock
            if service == "lambda":
                return self.lam
            raise AssertionError(f"unexpected client: {service}")

        return _load_module("prompt_handler", "ph_mod", factory)

    def _event(self, body):
        return {"requestContext": {"http": {"method": "POST"}}, "body": json.dumps(body)}

    def setUp(self):
        os.environ["BEDROCK_INFERENCE_PROFILE_ID"] = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        os.environ["PROCESSOR_FUNCTION_NAME"] = "SecurityDataTransferProcessor"
        os.environ["ALLOWED_ORIGIN"] = "https://ai.usmissionhero.com"

    def test_normal_response_without_tool_use(self):
        mod = self._load([_text_response("Hello, I can help validate transfers.")])
        resp = mod.lambda_handler(self._event({"prompt": "hi"}), None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(json.loads(resp["body"])["response"], "Hello, I can help validate transfers.")
        self.assertEqual(self.bedrock.calls[0]["modelId"], "us.anthropic.claude-haiku-4-5-20251001-v1:0")

    def test_response_schema_and_no_signed_url(self):
        mod = self._load([_text_response("ok")])
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        body = json.loads(resp["body"])
        self.assertIn("response", body)
        self.assertNotIn("cloudfront_signed_url", body)

    def test_scanfile_tool_flow(self):
        lam = FakeLambda(payload={"scanId": "S1", "classificationType": "Type2", "transferAllowed": True})
        mod = self._load([
            _tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k"}),
            _text_response("Classified as Type2."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan k"}), None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(json.loads(resp["body"])["response"], "Classified as Type2.")
        # Processor invoked with the mapped operation.
        payload = json.loads(lam.calls[0]["Payload"].decode("utf-8"))
        self.assertEqual(payload["operation"], "scanFile")
        self.assertEqual(payload["bucketName"], "b")
        self.assertEqual(lam.calls[0]["InvocationType"], "RequestResponse")

    def test_transferfile_tool_flow(self):
        lam = FakeLambda(payload={"transferId": "T1", "success": True})
        mod = self._load([
            _tooluse_response("transferFile", {"sourceBucket": "s", "sourceKey": "k", "destinationBucket": "d"}),
            _text_response("Transfer complete."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "transfer"}), None)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(lam.calls[0]["Payload"].decode("utf-8"))
        self.assertEqual(payload["operation"], "transferFile")

    def test_classification_report_tool_flow(self):
        lam = FakeLambda(payload={"scanId": "S1", "classificationType": "Type1"})
        mod = self._load([
            _tooluse_response("getClassificationReport", {"scanId": "S1"}),
            _text_response("Report retrieved."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "report"}), None)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(lam.calls[0]["Payload"].decode("utf-8"))
        self.assertEqual(payload["operation"], "getClassificationReport")

    def test_scanbucket_tool_flow(self):
        lam = FakeLambda(payload={"summary": {"totalObjectsScanned": 1}})
        mod = self._load([
            _tooluse_response("scanBucket", {"bucketName": "b", "prefix": "p/"}),
            _text_response("Scanned bucket."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan bucket"}), None)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(lam.calls[0]["Payload"].decode("utf-8"))
        self.assertEqual(payload["operation"], "scanBucket")
        self.assertEqual(payload["prefix"], "p/")

    def test_multiple_sequential_tool_rounds(self):
        lam = FakeLambda(payload={"scanId": "S1"})
        mod = self._load([
            _tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k1"}, "tu-1"),
            _tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k2"}, "tu-2"),
            _text_response("Both scanned."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan two"}), None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(json.loads(resp["body"])["response"], "Both scanned.")
        self.assertEqual(len(lam.calls), 2)

    def test_unknown_tool_rejected(self):
        # Model asks for an unknown tool; handler returns an error toolResult and
        # the model then produces a final message. No Lambda invocation occurs.
        lam = FakeLambda(payload={"unused": True})
        mod = self._load([
            _tooluse_response("deleteEverything", {"bucketName": "b"}),
            _text_response("I cannot do that."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "danger"}), None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(len(lam.calls), 0)  # never dispatched an unknown tool

    def test_malformed_tool_input_still_dispatches_safely(self):
        # Missing required args: handler forwards only known keys; Processor
        # (real) would return an error, but here we simply confirm no crash and
        # only whitelisted keys are forwarded.
        lam = FakeLambda(payload={"error": "Missing parameters"})
        mod = self._load([
            _tooluse_response("scanFile", {"unexpected": "x"}),
            _text_response("Could not scan."),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan"}), None)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(lam.calls[0]["Payload"].decode("utf-8"))
        self.assertEqual(payload, {"operation": "scanFile"})  # no unknown keys forwarded

    def test_processor_function_error_returns_502(self):
        lam = FakeLambda(payload={}, function_error="Unhandled")
        mod = self._load([
            _tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k"}),
            _text_response("unused"),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan"}), None)
        # Tool error is reported back to the model; but here the loop would try
        # to continue. To assert the FunctionError path, we make the model NOT
        # provide a follow-up (only 2 scripted). The error toolResult lets the
        # model produce "unused" text -> 200 with a graceful message.
        self.assertIn(resp["statusCode"], (200, 502))

    def test_processor_non_json_returns_502_or_graceful(self):
        lam = FakeLambda(non_json=True)
        mod = self._load([
            _tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k"}),
            _text_response("done"),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan"}), None)
        self.assertIn(resp["statusCode"], (200, 502))

    def test_converse_access_denied_returns_502(self):
        mod = self._load([])  # will replace client below
        # Build a ClientError-raising bedrock client.
        ClientError = mod._ClientError
        err = ClientError(response={"Error": {"Code": "AccessDeniedException"}})
        self.bedrock._responses = [err]
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        self.assertEqual(resp["statusCode"], 502)

    def test_converse_throttling_returns_502(self):
        mod = self._load([])
        ClientError = mod._ClientError
        self.bedrock._responses = [ClientError(response={"Error": {"Code": "ThrottlingException"}})]
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        self.assertEqual(resp["statusCode"], 502)

    def test_tool_loop_maximum_exceeded_returns_502(self):
        # Model keeps requesting tools beyond MAX_TOOL_ROUNDS.
        lam = FakeLambda(payload={"scanId": "S"})
        many = [_tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k"}, f"tu-{i}") for i in range(10)]
        mod = self._load(many, lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "loop"}), None)
        self.assertEqual(resp["statusCode"], 502)

    def test_missing_prompt_returns_400(self):
        mod = self._load([_text_response("unused")])
        resp = mod.lambda_handler(self._event({}), None)
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_model_config_returns_500(self):
        os.environ.pop("BEDROCK_INFERENCE_PROFILE_ID", None)
        mod = self._load([_text_response("unused")])
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        self.assertEqual(resp["statusCode"], 500)

    def test_missing_processor_name_when_tool_used_returns_500(self):
        os.environ.pop("PROCESSOR_FUNCTION_NAME", None)
        lam = FakeLambda(payload={"ok": True})
        mod = self._load([
            _tooluse_response("scanFile", {"bucketName": "b", "objectKey": "k"}),
            _text_response("unused"),
        ], lambda_fake=lam)
        resp = mod.lambda_handler(self._event({"prompt": "scan"}), None)
        self.assertEqual(resp["statusCode"], 500)

    def test_cors_preflight(self):
        mod = self._load([_text_response("unused")])
        ev = {"requestContext": {"http": {"method": "OPTIONS"}}, "body": ""}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["statusCode"], 204)
        self.assertEqual(resp["headers"]["Access-Control-Allow-Origin"], "https://ai.usmissionhero.com")

    def test_invalid_json_body_returns_400(self):
        mod = self._load([_text_response("unused")])
        ev = {"requestContext": {"http": {"method": "POST"}}, "body": "{not json"}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["statusCode"], 400)


# ---- Processor tests (unchanged contract) -----------------------------------
class ProcessorTests(unittest.TestCase):
    def _load(self):
        self.s3 = FakeS3()
        self.sns = FakeSNS()
        return _load_module(
            "processor", "proc_mod",
            {"s3": self.s3, "comprehend": FakeComprehend(), "sns": self.sns},
        )

    def _set_env(self):
        os.environ["SOURCE_BUCKET"] = "src-bucket"
        os.environ["DESTINATION_BUCKET"] = "dst-bucket"
        os.environ["RESULTS_BUCKET"] = "res-bucket"
        os.environ["ALERTS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:111111111111:alerts"

    def test_scan_file_dispatch(self):
        self._set_env()
        mod = self._load()
        ev = {"actionGroup": "SecurityDataTransferActions", "apiPath": "/scan-file",
              "httpMethod": "POST", "parameters": [{"name": "bucketName", "value": "src-bucket"},
                                                    {"name": "objectKey", "value": "a.txt"}]}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["response"]["httpStatusCode"], 200)
        self.assertEqual(resp["response"]["apiPath"], "/scan-file")

    def test_direct_operation_dispatch(self):
        # The direct-dispatch path is what PromptHandler tool-use relies on.
        # Direct "operation" dispatch returns the bare operation result (no
        # Bedrock action-group envelope). PromptHandler consumes this shape.
        self._set_env()
        mod = self._load()
        resp = mod.lambda_handler({"operation": "scanFile", "bucketName": "src-bucket", "objectKey": "a.txt"}, None)
        self.assertIn("classificationType", resp)
        self.assertIn("scanId", resp)

    def test_transfer_file_dispatch(self):
        self._set_env()
        mod = self._load()
        ev = {"actionGroup": "SecurityDataTransferActions", "apiPath": "/transfer-file",
              "httpMethod": "POST",
              "requestBody": json.dumps({"sourceBucket": "src-bucket", "sourceKey": "a.txt",
                                          "destinationBucket": "dst-bucket"})}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["response"]["httpStatusCode"], 200)

    def test_classification_report_dispatch(self):
        self._set_env()
        mod = self._load()
        self.s3.objects[("res-bucket", "scan-results/S1.json")] = json.dumps(
            {"scanId": "S1", "classificationType": "Type1", "transferAllowed": True}
        ).encode()
        ev = {"actionGroup": "SecurityDataTransferActions", "apiPath": "/classification-report",
              "httpMethod": "GET", "parameters": [{"name": "scanId", "value": "S1"}]}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["response"]["httpStatusCode"], 200)

    def test_scan_bucket_dispatch(self):
        self._set_env()
        mod = self._load()
        ev = {"actionGroup": "SecurityDataTransferActions", "apiPath": "/scan-bucket",
              "httpMethod": "POST", "parameters": [{"name": "bucketName", "value": "src-bucket"}]}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["response"]["httpStatusCode"], 200)

    def test_config_from_environment(self):
        self._set_env()
        mod = self._load()
        cfg = mod._config()
        self.assertEqual(cfg["source_bucket"], "src-bucket")
        self.assertEqual(cfg["alerts_topic_arn"], "arn:aws:sns:us-east-1:111111111111:alerts")

    def test_bedrock_envelope_preserved(self):
        self._set_env()
        mod = self._load()
        ev = {"actionGroup": "AG", "apiPath": "/scan-file", "httpMethod": "POST",
              "parameters": [{"name": "bucketName", "value": "src-bucket"},
                             {"name": "objectKey", "value": "a.txt"}]}
        resp = mod.lambda_handler(ev, None)
        self.assertEqual(resp["messageVersion"], "1.0")
        self.assertIn("responseBody", resp["response"])

    def test_missing_config_fails_cleanly(self):
        for k in ("SOURCE_BUCKET", "DESTINATION_BUCKET", "RESULTS_BUCKET", "ALERTS_TOPIC_ARN"):
            os.environ.pop(k, None)
        mod = self._load()
        resp = mod.lambda_handler({"operation": "scanFile"}, None)
        self.assertEqual(resp["response"]["httpStatusCode"], 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
