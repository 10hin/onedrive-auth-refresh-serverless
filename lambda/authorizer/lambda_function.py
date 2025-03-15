import datetime
import json
import logging
import os
import urllib.parse
import urllib.request
import uuid

import boto3


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(os.getenv('LOG_LEVEL', 'INFO'))

asm_client = boto3.client('secretsmanager')
dynamodb_client = boto3.client('dynamodb')

asm_secret_resp = asm_client.get_secret_value(SecretId=os.environ['CLIENT_SECRET_ARN'])
asm_secret_value = json.loads(asm_secret_resp['SecretString'])
CLIENT_ID = asm_secret_value['CLIENT_ID']
CLIENT_SECRET = asm_secret_value['CLIENT_SECRET']

AUTHORIZATION_STATES_TABLE_NAME = os.environ['AUTHORIZATION_STATES_TABLE_NAME']
TOKENS_TABLE_NAME = os.environ['TOKENS_TABLE_NAME']

def lambda_handler(event, context):
    req_ctx = event['requestContext']
    domain_name = req_ctx['domainName']
    http = req_ctx['http']
    method = http['method']
    path = http['path']

    if (method, path) == ('POST', '/'):
        return start_auth_session(domain_name)
    elif (method, path) == ('GET', '/authorized'):
        if 'queryStringParameters' not in event:
            raise Exception('Missing query string parameters')
        query_string = event['queryStringParameters']
        callback_code = query_string['code']
        callback_state = query_string['state']
        return complete_auth_session(callback_code, callback_state, domain_name)

def start_auth_session(domain_name):
    session_id = uuid.uuid4()
    item = {
        'SessionID': {
            'S': str(session_id),
        },
        'Expiration': {
            'N': str((datetime.datetime.now() + datetime.timedelta(seconds=30)).timestamp()),
        },
    }
    dynamodb_client.put_item(
        TableName=AUTHORIZATION_STATES_TABLE_NAME,
        Item=item,
    )
    return {
        'statusCode': 303,
        'headers': {
            'Location': 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize'
                        f'?client_id={CLIENT_ID}'
                        f'&response_type=code'
                        f'&redirect_uri={urllib.parse.quote(f'https://{domain_name}/authorized', safe='')}'
                        f'&response_mode=query'
                        f'&scope=offline_access%20User.Read'
                        f'&state={session_id}'
        },
    }

def complete_auth_session(code, state, domain_name):
    session_id = state
    session_resp = None
    try:
        session_resp = dynamodb_client.get_item(
            TableName=AUTHORIZATION_STATES_TABLE_NAME,
            Key={
                'SessionID': {
                    'S': session_id,
                },
            },
        )
    except Exception as e:
        LOGGER.warning('Failed to get session info from authorization-states table', e)
        return {
            'statusCode': 404,
        }

    session = session_resp['Item']
    expiration = float(session['Expiration']['N'])
    if expiration < datetime.datetime.now().timestamp():
        return {
            'statusCode': 404,
        }

    token_req = urllib.request.Request(
        'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
        method='POST',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        data=urllib.parse.urlencode({
            'client_id': CLIENT_ID,
            'scode': 'User.Read',
            'code': code,
            'redirect_uri': f'https://{domain_name}/authorized',
            'grant_type': 'authorization_code',
            'client_secret': CLIENT_SECRET,
        }).encode('utf-8'),
    )
    tokens_body = None
    try:
        with urllib.request.urlopen(token_req, ) as token_resp:
            if token_resp.status != 200:
                LOGGER.warning('Failed to get token', token_resp.read())
                return {
                    'statusCode': 400,
                }
            tokens_body = json.loads(token_resp.read())
    except:
        LOGGER.exception('Failed to get token')
        raise

    access_token = tokens_body['access_token']
    refresh_token = tokens_body['refresh_token']
    expires_in = tokens_body['expires_in']

    user_info_req = urllib.request.Request(
        'https://graph.microsoft.com/v1.0/me',
        method='GET',
        headers={
            'Authorization': f'Bearer {access_token}',
        },
    )
    user_id = None
    try:
        with urllib.request.urlopen(user_info_req) as user_info_resp:
            if user_info_resp.status != 200:
                LOGGER.warning('Failed to get user information', token_resp.read())
                return {
                    'statusCode': 400,
                }

            user_info = json.loads(user_info_resp.read())
            user_id = user_info['id']
    except:
        LOGGER.exception('Failed to get user information')
        raise

    token_item = {
        'ID': {
            'S': user_id,
        },
        'AccessToken': {
            'S': access_token,
        },
        'RefreshToken': {
            'S': refresh_token,
        },
        'ExpiresIn': {
            'N': str(expires_in),
        },
    }
    dynamodb_client.put_item(
        TableName=TOKENS_TABLE_NAME,
        Item=token_item,
    )

    return {
        'statusCode': 200,
    }
