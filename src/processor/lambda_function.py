"""
AI Validator — SecurityDataTransferProcessor (destination reconstruction).

Reconstructed from the authoritative recovered source
(local-only/evidence/ai-validator-recovery/git-history/
SecurityDataTransferProcessor_lambda_function.py), adapted for the destination
account (102726256311) architecture.

Behavior preserved:
  - Bedrock Agent action-group operations: /scan-file, /transfer-file,
    /classification-report, /scan-bucket (envelope preserved).
  - Direct "operation" dispatch (scanFile/transferFile/getClassificationReport/scanBucket).
  - S3 GetObject/PutObject/CopyObject/PutObjectTagging/ListObjectsV2,
    Comprehend DetectPiiEntities, SNS Publish.

Changes for destination:
  - Bucket names + alerts topic come from environment (no hard-coded source
    bucket names / source SNS ARN / source account id / email address).
  - No SSM, KMS, or Bedrock client in the Processor.

Runtime: python3.11, boto3 provided by the Lambda runtime (no third-party deps).
"""

import datetime
import json
import os
import re
import traceback
import uuid

import boto3
from botocore.exceptions import ClientError


class ConfigurationError(Exception):
    """Raised when required runtime configuration is missing."""


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(f"Missing required environment variable: {name}")
    return value


# Required destination configuration (wired by Terraform; no fake defaults).
def _config():
    return {
        "source_bucket": _require_env("SOURCE_BUCKET"),
        "destination_bucket": _require_env("DESTINATION_BUCKET"),
        "results_bucket": _require_env("RESULTS_BUCKET"),
        "alerts_topic_arn": _require_env("ALERTS_TOPIC_ARN"),
    }


PII_ENTITY_TYPES = [
    "BANK_ACCOUNT_NUMBER", "CREDIT_DEBIT_NUMBER", "CREDIT_DEBIT_CVV",
    "CREDIT_DEBIT_EXPIRY", "PIN", "EMAIL", "ADDRESS", "NAME", "PHONE",
    "SSN", "DATE_TIME", "PASSPORT_NUMBER", "DRIVER_ID", "URL", "AGE",
]

PHI_PATTERNS = {
    "medical_record_number": r"\b[A-Z]{2}\d{6}\b",
    "health_insurance_claim_number": r"\b\d{9}[A-Z]\b",
    "diagnosis_code": r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b",
    "npi_number": r"\b\d{10}\b",
    "prescription_information": r"(?i)\brx\s*#?\s*\d+\b",
}

s3_client = boto3.client("s3")
comprehend_client = boto3.client("comprehend")
sns_client = boto3.client("sns")


def _bedrock_response(status_code, content, action_group=None, api_path=None, http_method=None):
    if status_code == 200 and not isinstance(content, str):
        app_json = content
    else:
        app_json = {"message": content if isinstance(content, str) else json.dumps(content)}
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group or "SecurityDataTransferActions",
            "apiPath": api_path or "",
            "httpMethod": (http_method or "").upper(),
            "httpStatusCode": status_code,
            "responseBody": {"application/json": app_json},
        },
    }


def _safe_json_loads(text, default=None):
    if not text:
        return default if default is not None else {}
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default if default is not None else {}


def lambda_handler(event, context=None):
    try:
        cfg = _config()
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return _bedrock_response(500, "Service is not correctly configured.")

    try:
        # Direct operation dispatch
        if "operation" in event:
            op = event.get("operation")
            if op == "scanFile":
                return scan_file(event, cfg)
            if op == "transferFile":
                return transfer_file(event, cfg)
            if op == "getClassificationReport":
                return get_classification_report(event, cfg)
            if op == "scanBucket":
                return scan_bucket(event, cfg)
            return _bedrock_response(400, "Unsupported operation")

        # Bedrock Agent action-group dispatch
        if "actionGroup" in event and "apiPath" in event:
            action_group = event.get("actionGroup")
            api_path = event.get("apiPath")
            http_method = (event.get("httpMethod") or "").upper()

            raw_params = event.get("parameters", [])
            if isinstance(raw_params, list):
                params = {p["name"]: p.get("value") for p in raw_params if isinstance(p, dict) and "name" in p}
            elif isinstance(raw_params, dict):
                params = raw_params
            else:
                params = {}

            if api_path == "/scan-file" and http_method == "POST":
                result = scan_file({"bucketName": params.get("bucketName"), "objectKey": params.get("objectKey")}, cfg)
                return _bedrock_response(200, result, action_group, api_path, http_method)
            if api_path == "/transfer-file" and http_method == "POST":
                body = _safe_json_loads(event.get("requestBody") or "{}", {})
                result = transfer_file({
                    "sourceBucket": body.get("sourceBucket"),
                    "sourceKey": body.get("sourceKey"),
                    "destinationBucket": body.get("destinationBucket"),
                    "destinationKey": body.get("destinationKey"),
                }, cfg)
                return _bedrock_response(200, result, action_group, api_path, http_method)
            if api_path == "/classification-report" and http_method == "GET":
                result = get_classification_report({"scanId": params.get("scanId")}, cfg)
                return _bedrock_response(200, result, action_group, api_path, http_method)
            if api_path == "/scan-bucket" and http_method in ("POST", "GET"):
                body = _safe_json_loads(event.get("requestBody") or "{}", {})
                result = scan_bucket({
                    "bucketName": params.get("bucketName") or body.get("bucketName"),
                    "prefix": params.get("prefix") or body.get("prefix"),
                    "maxKeys": body.get("maxKeys"),
                }, cfg)
                return _bedrock_response(200, result, action_group, api_path, http_method)

            return _bedrock_response(400, f"Unsupported operation: {api_path} {http_method}",
                                     action_group, api_path, http_method)

        return _bedrock_response(400, "Unrecognized event")
    except Exception as exc:  # noqa: BLE001
        print(f"Unhandled exception: {exc}")
        traceback.print_exc()
        return _bedrock_response(500, "Internal error")


def _detect_pii(content):
    if not content:
        return []
    max_bytes = 99000
    content_bytes = content.encode("utf-8")
    if len(content_bytes) > max_bytes:
        content = content_bytes[:max_bytes].decode("utf-8", errors="replace")
    resp = comprehend_client.detect_pii_entities(Text=content, LanguageCode="en")
    return [
        {"Type": e["Type"], "Score": e["Score"], "BeginOffset": e["BeginOffset"], "EndOffset": e["EndOffset"]}
        for e in resp.get("Entities", []) if e.get("Type") in PII_ENTITY_TYPES
    ]


def _detect_phi(content):
    findings = []
    for name, pattern in PHI_PATTERNS.items():
        for match in re.finditer(pattern, content or ""):
            findings.append({"type": name, "location": f"{match.start()}-{match.end()}"})
    return findings


def _classify(pii, phi):
    if phi or any(f.get("Type") in ("SSN", "BANK_ACCOUNT_NUMBER", "CREDIT_DEBIT_NUMBER", "PASSPORT_NUMBER") for f in pii):
        return "Type3"
    if pii:
        return "Type2"
    return "Type1"


def scan_file(event, cfg):
    bucket_name = event.get("bucketName")
    object_key = event.get("objectKey")
    if not bucket_name or not object_key:
        return {"error": "Missing bucketName/objectKey", "errorCode": "MISSING_PARAMETERS"}
    try:
        obj = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        content = obj["Body"].read().decode("utf-8", errors="replace")
    except ClientError as exc:
        return {"error": "Error accessing file", "errorCode": exc.response.get("Error", {}).get("Code", "S3_ERROR")}

    pii = _detect_pii(content)
    phi = _detect_phi(content)
    classification = _classify(pii, phi)
    scan_id = str(uuid.uuid4())
    scan_result = {
        "scanId": scan_id, "bucketName": bucket_name, "objectKey": object_key,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "classificationType": classification, "piiFindings": pii, "phiFindings": phi,
        "transferAllowed": classification != "Type3",
    }
    try:
        s3_client.put_object(
            Bucket=cfg["results_bucket"], Key=f"scan-results/{scan_id}.json",
            Body=json.dumps(scan_result), ContentType="application/json",
        )
    except ClientError as exc:
        print(f"Warning: could not store scan result: {exc}")
    if classification == "Type3":
        _notify(cfg, {"type": "TYPE3_DETECTED", "scanId": scan_id, "objectKey": object_key})
    return {
        "scanId": scan_id, "classificationType": classification,
        "transferAllowed": classification != "Type3",
    }


def transfer_file(event, cfg):
    source_bucket = event.get("sourceBucket")
    source_key = event.get("sourceKey")
    destination_bucket = event.get("destinationBucket")
    destination_key = event.get("destinationKey") or source_key
    if not source_bucket or not source_key or not destination_bucket:
        return {"error": "Missing transfer parameters", "errorCode": "MISSING_PARAMETERS"}

    scan_result = scan_file({"bucketName": source_bucket, "objectKey": source_key}, cfg)
    if isinstance(scan_result, dict) and "error" in scan_result:
        return {"transferId": str(uuid.uuid4()), "success": False, "message": "Scan failed"}
    if not scan_result.get("transferAllowed", True):
        _notify(cfg, {"type": "TRANSFER_BLOCKED", "scanId": scan_result.get("scanId")})
        return {"transferId": str(uuid.uuid4()), "success": False,
                "message": "Transfer blocked (Type3 data)", "scanId": scan_result.get("scanId")}
    try:
        s3_client.copy_object(
            CopySource={"Bucket": source_bucket, "Key": source_key},
            Bucket=destination_bucket, Key=destination_key,
        )
        s3_client.put_object_tagging(
            Bucket=destination_bucket, Key=destination_key,
            Tagging={"TagSet": [
                {"Key": "DataClassification", "Value": scan_result.get("classificationType", "")},
                {"Key": "ScanId", "Value": scan_result.get("scanId", "")},
            ]},
        )
    except ClientError as exc:
        return {"transferId": str(uuid.uuid4()), "success": False,
                "message": "Transfer failed", "errorCode": exc.response.get("Error", {}).get("Code", "S3_ERROR")}
    return {"transferId": str(uuid.uuid4()), "success": True,
            "message": "Transfer completed", "scanId": scan_result.get("scanId")}


def get_classification_report(event, cfg):
    scan_id = event.get("scanId")
    if not scan_id:
        return {"error": "Missing scanId", "errorCode": "MISSING_SCAN_ID"}
    try:
        obj = s3_client.get_object(Bucket=cfg["results_bucket"], Key=f"scan-results/{scan_id}.json")
        scan_result = _safe_json_loads(obj["Body"].read().decode("utf-8"))
    except ClientError as exc:
        return {"error": "Report not found", "errorCode": exc.response.get("Error", {}).get("Code", "REPORT_NOT_FOUND")}
    return {
        "scanId": scan_id, "objectKey": scan_result.get("objectKey"),
        "classificationType": scan_result.get("classificationType"),
        "piiFindings": len(scan_result.get("piiFindings", [])),
        "phiFindings": len(scan_result.get("phiFindings", [])),
        "transferAllowed": scan_result.get("transferAllowed", False),
    }


def scan_bucket(event, cfg):
    bucket_name = event.get("bucketName")
    prefix = event.get("prefix") or ""
    max_keys = event.get("maxKeys")
    if not bucket_name:
        return {"error": "Missing bucketName", "errorCode": "MISSING_PARAMETERS"}
    results = []
    total = 0
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix) if prefix else paginator.paginate(Bucket=bucket_name)
        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith("/"):
                    continue
                if isinstance(max_keys, int) and total >= max_keys:
                    break
                results.append(scan_file({"bucketName": bucket_name, "objectKey": key}, cfg))
                total += 1
            if isinstance(max_keys, int) and total >= max_keys:
                break
    except ClientError as exc:
        return {"error": "Bucket scan failed", "errorCode": exc.response.get("Error", {}).get("Code", "BUCKET_SCAN_ERROR")}
    return {"summary": {"bucket": bucket_name, "prefix": prefix, "totalObjectsScanned": total},
            "sampleResults": results[:100]}


def _notify(cfg, payload):
    try:
        sns_client.publish(
            TopicArn=cfg["alerts_topic_arn"],
            Subject="AI Validator Security Alert",
            Message=json.dumps({**payload, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}),
        )
    except ClientError as exc:
        print(f"Warning: notification failed: {exc}")
