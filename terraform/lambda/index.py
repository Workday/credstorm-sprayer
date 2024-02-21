import requests
import boto3
import random, string


def lambda_handler(event, context):
    client = boto3.client('lambda')

    # Change IP from AWS Pool
    x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    changeip = client.update_function_configuration(
        FunctionName=context.function_name.strip(),
        Environment={
            'Variables': {'test': x}
        })

    # Wait for function to update
    waiter = client.get_waiter('function_active')
    waiter.wait(
        FunctionName=context.function_name.strip(),
        WaiterConfig={
            'Delay': 0
        }
    )

    # Send Proxied Request
    req = requests.Request(event['http_method'], url=event['url'], data=event['data'], headers=event['headers'])
    r = req.prepare()
    session = requests.Session()
    resp = session.send(r, allow_redirects=False)
    ip = requests.get('https://checkip.amazonaws.com')

    return {
        'STATUSCODE': resp.status_code,
        'BODYLENGTH': len(resp.text),
        'CREDENTIALS': event['username'] + ':' + event['password'],
        'IP': ip.text.strip(),
        'BODY': resp.text,
        'HEADERS': str(resp.headers)
    }
