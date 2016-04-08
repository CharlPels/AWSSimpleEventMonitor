"""
Routes and views for the flask application.
"""

from datetime import datetime
from FlaskWebProject import app
from flask import render_template,redirect
from flask import Flask, jsonify
from flask import request, Response #responce use for login part of the site
from datetime import datetime
from flask import abort
from functools import wraps #used for login part of the site
from flask_table import Table, Col, LinkCol, ButtonCol, DatetimeCol #for precenting tables
import json #Used for checking content of json variables comming from AWS
import os

import pypyodbc

#Redirecting all http traffic to https
"""
@app.before_request
def beforeRequest():
    if 'https' not in request.url:
        return redirect(request.url.replace('http', 'https'))
"""

class severity(Col):
    def td_format(self, content):
        if content == 'Error':
            return '<span style="color:#FF0000">' + content[:20] + "</SPAN>"
        elif content == 'Warning':
            return '<span style="color:#FFF801">' + content[:20] + "</SPAN>"
        else:
            return '<span style="color:#0101DF">' + content[:20] + "</SPAN>"

class priority(Col):
    def td_format(self, content):
        if content == 1:
            return '<span style="color:#FF0000">' + "  High" + "</SPAN>"
        elif content == 2:
            return '<span style="color:#FFF801">' + "  Medium" + "</SPAN>"
        else:
            return '<span style="color:#00FF00">' +  "  Low" + "</SPAN>"

class MoreSpace(Col):
    def td_format(self, content):
       return "" + content[:30]

class ShortTime(Col):
    def td_format(self, content):
       #We remove the seconds from the time
       return "" + content[:-7]

# Declare your table
class ItemTable(Table):
    #solved = LinkCol('solved', 'flask_link', url_kwargs=dict(id='id'))
    moreinfo = LinkCol('MoreInfo', 'awslog', url_kwargs=dict(id='id'))
    priority = priority(' Priority  ')
    lastevent = ShortTime(' Lastevent  ')
    logsource =  MoreSpace('Logsource  ') 
    instanceid = MoreSpace('Instanceid  ') 
    servername = MoreSpace('Servername  ')
    severity = severity('Severity  ')
    message = MoreSpace('Message  ')




print(os.environ['SimplePassword'])

#Start authentication code
def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == os.environ['SimpleUser'] and password == os.environ['SimplePassword']

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated
#End authentication code

#Connect to SQL Database if you want to use static information
"""
SQLconnectionString = ('Driver={SQL Server Native Client 11.0};'
        'Server=tcp:<servername>,1433;'
        'Database=ESNLSimpleMonitor;'
        'Uid=<username>;'
        'Pwd=<password>;'
        'Encrypt=yes;'
        'TrustServerCertificate=no;'
        'Connection Timeout=30')
"""
#is you get sql connection string from Azure or system enviroment settings
#on Windows create a enviroment setting with the following information
#variable: SQLCONNSTR_sqlDB
#value: Driver={SQL Server Native Client 11.0};Server=<servername>,1433;Database=<database>;Uid=<username>;Pwd=<password>;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30
try:
    SQLconnectionString = os.environ['SQLCONNSTR_sqlDB']
except:
    SQLconnectionString = "error"



@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    return redirect('/awslog')


@app.route('/contact')
def contact():
    """Renders the contact page."""
    return render_template(
        'contact.html',
        title='Contact',
        year=datetime.now().year,
        message='Your contact page.'
    )

@app.route('/awsitem/<int:id>')
@requires_auth
def flask_link(id):
    element = str(id)
    connection = pypyodbc.connect(SQLconnectionString)
    cursor = connection.cursor() 
    #SQLCommand = ("UPDATE events SET visible = 0 where id = " + element)
    SQLCommand = ("update events set visible = 0 where servername = (select servername from events where id = " + element + ") and information = (select information from events where id = " + element + ")")
    #SQLCommand = ("delete events where id = " + element)
    cursor.execute(SQLCommand)
    cursor.close()
    connection.commit()  
    connection.close()
    return redirect('/awslog')


@app.route('/about')
def about():
    """Renders the about page."""
    return render_template(
        'about.html',
        title='About',
        year=datetime.now().year,
        message='Your application description page.'
    )


@app.route('/awslog')
@app.route('/awslog/<int:id>')
@requires_auth
def awslog(id=0):
    element = str(id)
    connection = pypyodbc.connect(SQLconnectionString)
    cursor = connection.cursor() 
    SQLCommand = ("select priority, replace(replace([instanceid],'arn:aws:sns:',''),'1d6dfeb2-c53a-447b-a156-64242c358a79','') as 'instanceid', replace(servername,'ace.nl.capgemini.com','') as servername,  logsource, severity, Information as 'message', min(id) as [ID], convert(varchar, max([logtime]), 114) as lastevent from events where visible = 1 group by [priority],[instanceid],[servername],[logsource],[severity],[Information],[SubscribeURL],[visible] order by [priority] ,[id]")
    #SQLCommand = ("select top 1 [instanceid], left([Information],20) as 'message', servername from events where id=1577")
    cursor.execute(SQLCommand) 
    #Drop all results in the items list
    items = cursor.fetchall()

    table = ItemTable(items)
    if not element == "0":
        SQLCommand = ("select replace(replace([instanceid],'arn:aws:sns:',''),'1d6dfeb2-c53a-447b-a156-64242c358a79','') as 'instanceid', replace(servername,'ace.nl.capgemini.com','') as servername, CONVERT(VARCHAR(20),logtime,113) as logtime,logsource, severity, Information as 'message', id from events where visible = 1 and id = " + element)
        cursor.execute(SQLCommand)
        info=cursor.fetchone()
        eventinstanceid=info[0]
        eventservername=info[1]
        eventlogtime=info[2]
        eventlogsource=info[3]
        eventseverity=info[4]
        eventInformation=info[5]
        eventid=info[6]
        #counter to show how many of the same event are reported   
        SQLCommand = ("select count(id) from events where servername = (select servername from events where id = " + element + ") and information = (select information from events where visible = 1 and id =" + element +")")
        cursor.execute(SQLCommand)
        info=cursor.fetchone()
        errorcount=info[0]
        cursor.close()
        connection.close()
    else:
        eventinstanceid=""
        eventservername=""
        eventlogtime=""
        eventlogsource=""
        eventseverity=""
        eventInformation=""
        eventid=""
        errorcount=""

    return render_template(
        'AWSmonitor.html',
        title='EventViewer',
        year=datetime.now().year,
        table=table,
        eventinstanceid=eventinstanceid,
        eventservername=eventservername,
        eventlogtime=eventlogtime,
        eventlogsource=eventlogsource,
        eventseverity=eventseverity,
        eventInformation=eventInformation,
        eventid=eventid,
        errorcount=errorcount
    )


#Used for our try tool and will precent a popup when a new event comes in
@app.route('/api/v1.0/lastevent', methods=['GET'])
@requires_auth
def lastevent():
        connection = pypyodbc.connect(SQLconnectionString)
        cursor = connection.cursor()
        SQLCommand = ("select top 1 [id],[instanceid],[servername],[severity],[Information] from [dbo].[Events] where visible = 1 order by id desc")
        #Values = [instanceidresult,request.json.get('servername'),request.json.get('logsource'),severity,Informationresult,visible]
        cursor.execute(SQLCommand)
        info=cursor.fetchone()
        if info is not None:       
            logentry = {
              'id': info[0],
              'instanceid': info[1],
              'servername': info[2],
              'severity': info[3],
              'Information': info[4]
           }
        else:
            logentry = {
              'id': "",
              'instanceid': "",
              'servername': "",
              'severity': "",
              'Information': ""
            }
        connection.commit() 
        connection.close()
        return jsonify({'logentry': logentry}), 201

@app.route('/api/v1.0/logs/insert', methods=['POST','GET'])
def insert():
    print("start")
    if not request.json or not 'instanceid' in request.json:
        print(request.json)
        abort(400)
    

    instanceid=request.json['instanceid']
    Information=request.json.get('Information')
    severity = request.json.get('severity')
    try:
        #Section for handeling AWS SNS topics
        instanceidresult=instanceid
        Informationresult=Information
        if ((instanceid).split(":")[5]) == "AWS-config-topic":
            visible=0
            instanceidresult=((instanceid).split(":")[5])
            inventory = json.loads(Information)
            #Informationresult=dict.items(Information["configurationItemDiff"])
            Informationresult=inventory["configurationItemDiff"]["changedProperties"]
            Informationresult=str(Informationresult)
        if ((instanceid).split(":")[5]) == "EnvironmentIssues":
            instanceidresult=((instanceid).split(":")[5])
            severity = "Alarm"
            inventory = json.loads(Information)
            Informationresult =(inventory["AlarmName"] +" : "+ inventory["AlarmDescription"])
            visible=1
        if ((instanceid).split(":")[5]) == "CloudWatchAlarmsForCloudTrail-AlarmNotificationTopic-1W61SN3URDERR":
            instanceidresult=((instanceid).split(":")[5])
            severity = "Alarm"
            inventory = json.loads(Information)
            Informationresult =(inventory["AlarmName"] +" : "+ inventory["AlarmDescription"])
            visible=1      
    except:
        instanceidresult=instanceid
        Informationresult = Information
        visible=1
    logentry = {
        'instanceid': instanceidresult,
        'servername': request.json.get('servername', ""),
        'logsource': request.json.get('logsource', ""),
        'severity': request.json.get('severity', ""),
        'Information': Informationresult
    }
    if visible == 1:
        connection = pypyodbc.connect(SQLconnectionString)
        cursor = connection.cursor()
        SQLCommand = ("INSERT INTO events (instanceid, servername, logtime, logsource, severity, Information, visible) VALUES (?,?,(getdate()),?,?,?,?)")
        Values = [instanceidresult,request.json.get('servername'),request.json.get('logsource'),severity,Informationresult,visible]
        cursor.execute(SQLCommand,Values) 
        connection.commit() 
        connection.close()
        return jsonify({'logentry': logentry}), 201



