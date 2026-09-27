"""
Local static unit tests for reconstructed AI Validator Lambda handlers.
No AWS calls: boto3 clients are stubbed. Run with: py -m unittest -v
(from C:\\USMISSIONHERO\\products\\ai\\src)

These tests exercise dispatch/response-contract/config behavior only.
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
class FakeAgentRuntime:
    def __init__(self, chunks):
        self._chunks = chunks
        self.calls = []

    def invoke_agent(self, **kwargs):
        self.calls.append(kwargs)
        completion = [{"chunk": {"bytes": c.encode("utf-8")}} for c in self._chunks]
        return {"completion": completion}


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
        outer = self

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
    """Load src/<rel_dir>/lambda_function.py with a stubbed boto3 module."""
    path = os.path.join(SRC, rel_dir, "lambda_function.py")
    fake_boto3 = types.ModuleType("boto3")

    def client(service_name, *a, **k):
        return boto3_client_map[service_name]

    fake_boto3.client = client
    # Minimal botocore.exceptions.ClientError
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


# ---- PromptHandler tests ----------------------------------------------------
class PromptHandlerTests(unittest.TestCase):
    def _load(self, chunks=("Hello ", "world")):
        self.agent = FakeAgentRuntime(list(chunks))
        return _load_module("prompt_handler", "ph_mod", {"bedrock-agent-runtime": self.agent})

    def _event(self, body):
        return {"requestContext": {"http": {"method": "POST"}}, "body": json.dumps(body)}

    def test_missing_prompt_returns_400(self):
        os.environ["BEDROCK_AGENT_ID"] = "AID"
        os.environ["BEDROCK_AGENT_ALIAS_ID"] = "ALIAS"
        mod = self._load()
        resp = mod.lambda_handler(self._event({}), None)
        self.assertEqual(resp["statusCode"], 400)

    def test_valid_prompt_invokes_agent_with_config(self):
        os.environ["BEDROCK_AGENT_ID"] = "AID123"
        os.environ["BEDROCK_AGENT_ALIAS_ID"] = "ALIAS123"
        mod = self._load(chunks=("foo", "bar"))
        resp = mod.lambda_handler(self._event({"prompt": "hi"}), None)
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(self.agent.calls[0]["agentId"], "AID123")
        self.assertEqual(self.agent.calls[0]["agentAliasId"], "ALIAS123")

    def test_streamed_chunks_combine(self):
        os.environ["BEDROCK_AGENT_ID"] = "AID"
        os.environ["BEDROCK_AGENT_ALIAS_ID"] = "ALIAS"
        mod = self._load(chunks=("Hello ", "world"))
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        self.assertEqual(json.loads(resp["body"])["response"], "Hello world")

    def test_response_only_no_signed_url(self):
        os.environ["BEDROCK_AGENT_ID"] = "AID"
        os.environ["BEDROCK_AGENT_ALIAS_ID"] = "ALIAS"
        mod = self._load()
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        body = json.loads(resp["body"])
        self.assertIn("response", body)
        self.assertNotIn("cloudfront_signed_url", body)

    def test_missing_agent_id_config_failure(self):
        os.environ.pop("BEDROCK_AGENT_ID", None)
        os.environ["BEDROCK_AGENT_ALIAS_ID"] = "ALIAS"
        mod = self._load()
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        self.assertEqual(resp["statusCode"], 500)

    def test_missing_agent_alias_config_failure(self):
        os.environ["BEDROCK_AGENT_ID"] = "AID"
        os.environ.pop("BEDROCK_AGENT_ALIAS_ID", None)
        mod = self._load()
        resp = mod.lambda_handler(self._event({"prompt": "x"}), None)
        self.assertEqual(resp["statusCode"], 500)


# ---- Processor tests --------------------------------------------------------
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
