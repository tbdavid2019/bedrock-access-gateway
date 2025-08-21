import json
import os
from typing import Annotated

import boto3
from botocore.exceptions import ClientError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.setting import DEFAULT_API_KEYS

api_key_env = os.environ.get("API_KEY")
api_key_param = os.environ.get("API_KEY_PARAM_NAME")
api_key_secret_arn = os.environ.get("API_KEY_SECRET_ARN")

# 優先使用 API_KEY 環境變數，其次 SSM/Secrets Manager，最後 fallback 預設值
if api_key_env:
    api_key = api_key_env
elif api_key_param:
    try:
        ssm = boto3.client("ssm")
        api_key = ssm.get_parameter(Name=api_key_param, WithDecryption=True)["Parameter"]["Value"]
    except Exception as e:
        raise RuntimeError(f"Unable to retrieve API KEY from SSM: {e}")
elif api_key_secret_arn:
    try:
        sm = boto3.client("secretsmanager")
        response = sm.get_secret_value(SecretId=api_key_secret_arn)
        if "SecretString" in response:
            secret = json.loads(response["SecretString"])
            api_key = secret["api_key"]
        else:
            raise RuntimeError("SecretString not found in secret value")
    except ClientError:
        raise RuntimeError("Unable to retrieve API KEY, please ensure the secret ARN is correct")
    except KeyError:
        raise RuntimeError('Please ensure the secret contains a "api_key" field')
    except Exception as e:
        raise RuntimeError(f"Unable to retrieve API KEY from Secrets Manager: {e}")
else:
    # For local use only.
    api_key = DEFAULT_API_KEYS

security = HTTPBearer()


def api_key_auth(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    if credentials.credentials != api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
