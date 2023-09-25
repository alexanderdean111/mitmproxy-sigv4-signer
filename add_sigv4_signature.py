
import logging
import json
import os

import mitmproxy

import sigv4_signer

class AddSigV4Signature:
    def __init__(self):
        self._logger = logging.getLogger("AddSigV4Signature")
        self._sigV4Signer = sigv4_signer.SigV4Signer()

    def request(self, flow):
        if "Authorization" in flow.request.headers:
            if "AWS4-HMAC-SHA256" in flow.request.headers['Authorization']:
                self._logger.info("got SigV4 signed request")
                method = flow.request.method
                url = flow.request.url
                headers = dict(flow.request.headers)
                params = dict(flow.request.query)
                bodyBytes = flow.request.content

                req = self._sigV4Signer.generateSignedRequest(method, url, params, headers, bodyBytes)
                # convert botocore headers object to mitmproxy headers object
                headerTuples = list()
                for header in req.headers:
                    headerTuples.append((bytes(header, "utf8"), bytes(req.headers[header], "utf8")))
                newFlowHeaders = mitmproxy.http.Headers(headerTuples)

                # update headers
                flow.request.headers = newFlowHeaders

addons = [AddSigV4Signature()]








