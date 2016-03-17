from __future__ import print_function


import json
import requests

print('Loading function')


def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    #print((event["Records"][0]["EventSubscriptionArn"]).split(":")[2])
    #print(event["Records"][0]["Sns"]["Message"])
    #print(event["Records"][0]["Sns"]["Subject"])
    #print(event["Records"][0]["EventSource"])
    data = {
    'instanceid': event["Records"][0]["EventSubscriptionArn"],
    'servername': event["Records"][0]["EventSource"],
    'logsource': event["Records"][0]["EventSource"],
    'severity': event["Records"][0]["Sns"]["Subject"],
	'Information': event["Records"][0]["Sns"]["Message"]
	}
    print(data)
    headers = {'Content-Type': 'application/json'}
    r = requests.post("https://<<<--- your url here --->>>/api/v1.0/logs/insert", data=json.dumps(data), headers=headers)
    return  # Echo back the first key value

