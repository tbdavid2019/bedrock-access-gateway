import os

DEFAULT_API_KEYS = "bedrock"

API_ROUTE_PREFIX = os.environ.get("API_ROUTE_PREFIX", "/api/v1")

TITLE = "Amazon Bedrock Proxy APIs"
SUMMARY = "OpenAI-Compatible RESTful APIs for Amazon Bedrock"
VERSION = "0.1.0"
DESCRIPTION = """
Use OpenAI-Compatible RESTful APIs for Amazon Bedrock models.
"""

DEBUG = os.environ.get("DEBUG", "false").lower() != "false"
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "anthropic.claude-3-sonnet-20240229-v1:0")
DEFAULT_EMBEDDING_MODEL = os.environ.get("DEFAULT_EMBEDDING_MODEL", "cohere.embed-multilingual-v3")
ENABLE_CROSS_REGION_INFERENCE = os.environ.get("ENABLE_CROSS_REGION_INFERENCE", "true").lower() != "false"
ENABLE_APPLICATION_INFERENCE_PROFILES = os.environ.get("ENABLE_APPLICATION_INFERENCE_PROFILES", "true").lower() != "false"
ENABLE_WARMUP_PINGER = os.environ.get("ENABLE_WARMUP_PINGER", "false").lower() == "true"
WARMUP_INTERVAL_SECONDS = int(os.environ.get("WARMUP_INTERVAL_SECONDS", "600"))
WARMUP_TIMEZONE = os.environ.get("WARMUP_TIMEZONE", "Asia/Taipei")
WARMUP_START_HOUR = int(os.environ.get("WARMUP_START_HOUR", "8"))
WARMUP_END_HOUR = int(os.environ.get("WARMUP_END_HOUR", "18"))
# Docker --env-file 不會展開 ${VAR}，這裡做一次簡易展開
_warmup_model_raw = os.environ.get("WARMUP_MODEL", DEFAULT_MODEL)
if _warmup_model_raw.strip() in ("${DEFAULT_MODEL}", "$DEFAULT_MODEL"):
    WARMUP_MODEL = DEFAULT_MODEL
else:
    WARMUP_MODEL = _warmup_model_raw
