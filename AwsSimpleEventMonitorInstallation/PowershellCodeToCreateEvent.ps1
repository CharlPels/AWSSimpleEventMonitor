#Here is a powershell sample to send messages to the simple event monitor

$body = @{
    'instanceid'= "your instance or server name"
    'Information'= "Information"
    'servername'= "your instance or server name"
    'logsource'= "logsource"
    'severity'= "severity like error / worning / information"
}
$monitorURL = "https://<<<-- your server url -->>>/api/v1.0/logs/insert"
ConvertTo-Json $body
Invoke-RestMethod -Method Post -Uri $monitorURL -Body (ConvertTo-Json $body) -ContentType application/json

