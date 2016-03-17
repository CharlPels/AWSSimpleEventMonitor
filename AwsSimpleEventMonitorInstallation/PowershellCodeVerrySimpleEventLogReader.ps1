#If you would run this code every minute on your server
#It will pick up your events and send them to the SimpleMonitor
#Can also be placed in a loop of scheduled tasks offcource.
#Remember it is just a sample you can alter it to fit your needs


$monitorURL = "https://<<<-- your server url -->>>/api/v1.0/logs/insert"



#Sending event to our monitor system
function send-EventsToLog($instanceid,$Information,$servername,$logsource,$severity)
{
$body = @{
    'instanceid'= $instanceid
    'Information'= $Information
    'servername'= $servername
    'logsource'= $logsource
    'severity'= $severity
}

    ConvertTo-Json $body
    Invoke-RestMethod -Method Post -Uri $monitorURL -Body (ConvertTo-Json $body) -ContentType application/json
}

#Collect events from Windows eventlogs
function get-WindowsEvents()
{

    [datetime]$endtime=get-date
    [datetime]$starttime=$endtime.AddDays(-0.0007) #means take logs from 1 min before
    #[datetime]$starttime=$endtime.AddDays(-1)

    #$eventlog=Get-WinEvent -FilterHashtable @{ProviderName="Microsoft-Windows-TerminalServices-Gateway";starttime=$starttime;endtime=$endtime;id=300} 

    #First We take application logs
    $eventlog=Get-WinEvent -FilterHashtable @{LogName="application";starttime=$starttime;endtime=$endtime;level=2} -ErrorAction SilentlyContinue
    $eventlog+=Get-WinEvent -FilterHashtable @{LogName="application";starttime=$starttime;endtime=$endtime;level=3} -ErrorAction SilentlyContinue 
    #Security logs
    $c = [System.Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditFailure
    $eventlog+=Get-WinEvent -FilterHashtable @{LogName="security";starttime=$starttime;endtime=$endtime;keywords=$c.value__} -ErrorAction SilentlyContinue
    #Now the system logs
    $eventlog+=Get-WinEvent -FilterHashtable @{LogName="system";starttime=$starttime;endtime=$endtime;level=2} -ErrorAction SilentlyContinue 
    $eventlog+=Get-WinEvent -FilterHashtable @{LogName="system";starttime=$starttime;endtime=$endtime;level=3} -ErrorAction SilentlyContinue
	#Now we proccess events
    foreach($event in $eventlog)
    {
        if ($event.Id -ne 4673 -and $event.Id -ne 5152 -and $event.Id -ne 4656)
        {
            #Send the events to our loging tool
            send-EventsToLog -instanceid $instanceid -Information $event.Message -servername $event.MachineName -logsource $event.LogName -severity $event.LevelDisplayName

        }

    }
}
