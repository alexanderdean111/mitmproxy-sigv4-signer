#!/usr/bin/env python

import sys, os, base64, datetime, hashlib, hmac

# replace with name of credential to use from ~/.aws/credentials
# otherwise will try to pull and resign with whatever cred was used
# in the request

USE_CRED = None

def load_creds_file():
    creds_file = "{}/.aws/credentials".format(os.environ.get("HOME"))
    with open(creds_file) as f:
        lines = f.readlines()

    entries = {}
    while lines:
        line = lines.pop(0)
        if line.strip().startswith('[') and line.strip().endswith(']'):
            name = line.strip()[1:-1]
            entry = {}
            while lines:
                next_line = lines.pop(0)
                if next_line.strip().startswith('[') and line.strip().endswith(']'):
                    lines = [line] + lines
                    break
                try:
                    param, value = next_line.split('=')
                    param = param.strip()
                    value = value.strip()
                    entry[param] = value
                except:
                    break
            entries[name] = entry
    return entries


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def request(flow):
    if "AWS4-HMAC-SHA256" in flow.request.headers["Authorization"]:
        t = datetime.datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

        authz_header = flow.request.headers["Authorization"]
        authz_header_items = authz_header.split()[1:]
        authz_header_items = {x.split('=')[0]:x.split('=')[1][:-1] for x in authz_header_items}
        method = flow.request.method
        service = authz_header_items["Credential"].split('/')[3]
        host = flow.request.host
        region = authz_header_items["Credential"].split('/')[2]

        request_cred = authz_header_items["Credential"].split('/')[0]
        file_creds = load_creds_file()
        access_key = None
        secret_key = None
        if USE_CRED is None:
            # no credential selected, try to use whatever is already in
            # the request
            #print("no credential selected, trying to find key for {}".format(request_cred))
            for name in file_creds:
                if file_creds[name]["aws_access_key_id"] == request_cred:
                    access_key = file_creds[name]["aws_access_key_id"]
                    secret_key = file_creds[name]["aws_secret_access_key"]
                    #print("found creds for access key {} in ~/.aws/credentials (entry \"[{}]\")".format(name))
                    break
        elif USE_CRED in file_creds:
            #print("using credential \"[{}]\"".format(USE_CRED))
            access_key = file_creds[USE_CRED]["aws_access_key_id"]
            secret_key = file_creds[USE_CRED]["aws_secret_access_key"]

        elif access_key is None or secret_key is None:
            #print("can't find creds")
            pass
        else:
            #print("WTF even happened")
            raise ValueError("WTF")

        try:
            request_parameters = flow.request.path.split('?')[1]
        except IndexError:
            request_parameters = ""

        # build the authorization header according to 
        # https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
        canonical_uri = flow.request.path.split('?')[0]
        canonical_querystring = request_parameters
        canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
        signed_headers = 'host;x-amz-date'
        payload_hash = hashlib.sha256(flow.request.content).hexdigest()
        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
        string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        signing_key = getSignatureKey(secret_key, datestamp, region, service)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
        headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}

        flow.request.headers["x-amz-date"] = amzdate
        flow.request.headers["Authorization"] = authorization_header
    else:
        flow.request.headers["foo"] = "rawr"
