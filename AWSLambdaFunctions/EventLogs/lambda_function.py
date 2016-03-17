import base64
import gzip
import json
import requests

from StringIO import StringIO

def lambda_handler(event,context):
    decoded_data = event['awslogs']['data'].decode("base64")
    gunzipped_data = gzip.GzipFile(fileobj=StringIO(decoded_data)).read()
    #print("data : " + gunzipped_data)
    #print("----")
    #json_string = json.dumps(gunzipped_data)
    #print(json_string)
    #print("----")	
    inventory = json.loads(gunzipped_data)
    #print(inventory)
    logGroup = (inventory["logGroup"])
    logStream = (inventory["logStream"])

    for u in (inventory["logEvents"]):
        severity = "Unknown"
        eventinfo = (u["message"])
        servername = "Unknown"
        Information = eventinfo
        DoNotLog=0
        #Windows Information events
        if "[Information]" in (eventinfo):
            severity = "Information"
            servername = ((eventinfo).split("[")[5])
            Information = ((eventinfo).split("[")[6][:-1]) #With :-1 we remove the last character
            DoNotLog=1 #for now we don't log information events
        #Windows Warning events
        if "[Warning]" in (eventinfo):
            severity = "Warning"
            servername = ((eventinfo).split("[")[5])
            Information = ((eventinfo).split("[")[6][:-1])#With :-1 we remove the last character
        
        #Windows Error events
        if "[Error]" in (u["message"]):
            severity = "Error"
            servername = ((u["message"]).split("[")[5])
            Information = ((u["message"]).split("[")[6][:-1])#With :-1 we remove the last character

        #Windows Error events
        if "[Security]" in (u["message"]):
            severity = "Security"
            servername = ((u["message"]).split("[")[5])
            Information = ((u["message"]).split("[")[6][:-1])#With :-1 we remove the last character
        if "[5158]" in (u["message"]): DoNotLog=1 #Windows Firewall filtering
        if "[4658]" in (u["message"]): DoNotLog=1 #removeble storage handle
        if "[4702]" in (u["message"]): DoNotLog=1 #A scheduled task was updated
        if "[4673]" in (u["message"]): DoNotLog=1 #A privileged service was called	
        if "[4663]" in (u["message"]): DoNotLog=1 #An attempt was made to access an object.
		
        #If DoNotLog is 0 meaning we should save the event we will upload it to our simple monitor
        if DoNotLog == 0:    
            data = {
            'instanceid': logStream,
            'servername': servername,
            'logsource': "CloudwatchLog: " + logGroup,
            'severity': severity,
            'Information': Information
            }
            print(data)
            headers = {'Content-Type': 'application/json'}
            r = requests.post("https://<<<--- your url here --->>>/api/v1.0/logs/insert", data=json.dumps(data), headers=headers)

