"""Entry point for a real run: uvicorn portal.main:app (see README)."""

import boto3

from portal.app import create_app
from portal.granter import StsGranter
from portal.settings import Settings

app = create_app(Settings(), StsGranter(boto3.client("sts")))
