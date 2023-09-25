import os
import json
import logging
import sys
import copy
from urllib.parse import urlparse

import botocore
import boto3
import requests

_logger = logging.getLogger("SigV4Signer")

logging.basicConfig(
    format="%(asctime)s | %(levelname)8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S%z",
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

class SigV4Signer:
    def __init__(self, profile_name="default"):
        # load credentials from 'default' profile
        self._session = boto3.session.Session(profile_name=profile_name)
        self._credential = self._session.get_credentials().get_frozen_credentials()
        _logger.info(f"loaded credential {self._credential.access_key} from 'default' profile")

    def generateSignedRequest(self, method, url, params, headers, bodyBytes, service=None, region=None):
        # feed information into botocore and have it generate the signature for us

        _logger.info(f"generating SigV4 auth header for {method} {url}")
        req = botocore.awsrequest.AWSRequest(
            method=method,
            url=url,
            data=bodyBytes,
            params=params,
            headers=headers
        )

        # if region or service not provided, try to guess from existing auth header
        if not service or not region:
            _logger.info("trying to parse service/region from request")
            if "Authorization" in req.headers:
                # find "Credential=" so the first item in our split() is the one we want
                credentialIndex = req.headers['Authorization'].find("Credential=")
                credentialHeader = req.headers['Authorization'][credentialIndex:].split(",")[0]
                credentialValues = credentialHeader.split("=")[1]

                reqAccessKey = credentialValues.split("/")[0]
                reqRegion = credentialValues.split("/")[2]
                reqService = credentialValues.split("/")[3]

                _logger.info(f"got service: {reqService} and region: {reqRegion}")

        if not service:
            _logger.debug(f"service not provided, using {reqService} from request")
            service = reqService

        if not region:
            _logger.debug("region not provided, using {reqRegion} from request")
            region = reqRegion

        botocore.auth.SigV4Auth(self._credential, service, region).add_auth(req)
        return req

    def parseAWSAuthHeader(self, s):
        sigv4AuthHeaderStart = "AWS4-HMAC-SHA256"
        if not s.startswith(sigv4AuthHeaderStart):
            _logger.error(f"unable to parse header: {s}")
            return None
        authHeaderRaw = s[len(sigv4AuthHeaderStart):].strip()
        authHeaderParts = authHeaderRaw.split(",")
        authHeader = {x.split("=")[0].strip(): x.split("=")[1].strip() for x in authHeaderParts}

        return authHeader


if __name__ == "__main__":

    sigV4Signer = SigV4Signer()
    # generate an STS get_caller_identity request and sign with botocore
    method = "POST"
    host = "sts.amazonaws.com"
    path = "/"
    headers = {
        "Host": "sts.amazonaws.com",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent": "aws-cli/1.18.69 Python/3.8.10 Linux/5.4.0-162-generic botocore/1.16.19",
    }
    bodyBytes = "Action=GetCallerIdentity&Version=2011-06-15"
    region = "us-east-1"
    service = "sts"

    # generateSignedRequest(self, method, url, params, headers, bodyBytes, service=None, region=None):

    req = sigV4Signer.generateSignedRequest(method, f"https://{host}{path}", None, headers=headers, bodyBytes=bodyBytes, service=service, region=region)

    # parse out the signature so we can log it
    sigv4_auth_header = req.headers['Authorization']
    sigv4_auth_header_parts = [x.strip() for x in sigv4_auth_header.split(",")]
    for part in sigv4_auth_header_parts:
        if part.startswith("Signature"):
            sigv4_signature = part.split("=")[1]
    _logger.info(f"generated SigV4 signature: {sigv4_signature}")

    # prepare requests
    req = req.prepare()
    badSigReq = copy.deepcopy(req)

    # replace the "Signature" part of the header with all 0's to make it fail
    badSigHeader = badSigReq.headers['Authorization']
    sigIndex = badSigHeader.find("Signature=")
    badSigHeader = f"{badSigHeader[0:sigIndex]}Signature={'0'*64}"
    badSigReq.headers['Authorization'] = badSigHeader

    _logger.info(f"sending request with bad signature to ensure it is rejected")
    badResponse = requests.request(method=badSigReq.method, url=badSigReq.url, headers=badSigReq.headers, data=badSigReq.body)
    if badResponse.status_code == 403 and "does not match" in badResponse.text:
        _logger.info(f"bad request rejected")
    else:
        _logger.error(f"intentionally bad request wasn't rejected with 403, check the response:\n{badResponse.text}")
        raise ValueError(f"intentionally bad signature not properly rejected")


    _logger.info(f"checking good signature:\n{req.headers['Authorization']}")
    response = requests.request(method=req.method, url=req.url, headers=req.headers, data=req.body)
    if response.status_code == 200:
        _logger.info(f"Request accepted, signing is working:\n{response.text}")
    else:
        _logger.error(f"Request failed, signing may not be working:\n{response.text}")

    #print(req.headers['Authorization'])









