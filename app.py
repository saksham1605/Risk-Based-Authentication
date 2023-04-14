from flask import Flask, render_template, request, redirect, session
import os
import datetime
from user_agents import parse
import pytz
import requests
import random
import re
import pickle
import pandas as pd
from category_encoders.one_hot import OneHotEncoder
from users import users
import geoip2.database


app = Flask(__name__)
app.secret_key = os.urandom(24)


# Function to get the user's IP address
def get_ip():
    ip = request.remote_addr
    return ip

def getasn_fromip(ip_address):
    # response = requests.get(f'https://ipinfo.io/{ip_address}')
    # if 'bogon' in response.json():
    #     if(response.json()['bogon']==True):
    #         return [int('0'),'US']
    # asn_number = response.json()['org']
    # asn_number=asn_number.split()[0][2:]
    # country_code = response.json()['country']
    reader = geoip2.database.Reader('GeoLite2-Country_20230414/GeoLite2-Country.mmdb')
    try:
        response = reader.country(ip_address)
        country_code=response.country.iso_code
        reader = geoip2.database.Reader('GeoLite2-ASN_20230414/GeoLite2-ASN.mmdb')
        response = reader.asn(ip_address)
        asn_number=response.autonomous_system_number
    except:
        country_code='US'
        asn_number=0
    print(country_code,asn_number)
    return [int(asn_number),country_code]

def convertToSeconds(s):
    d = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
    # extract the hour component of the datetime object
    hour = d.hour
    # determine whether it's day, evening, or night based on the hour
    if hour >= 6 and hour < 18:
        time_of_day = '0'
    elif hour >= 18 and hour < 22:
        time_of_day = '1'
    else:
        time_of_day = '2'
    return time_of_day


def send_email(ver,rec):
    url = "https://api.sendinblue.com/v3/smtp/email"
    headers = {
        "Content-Type": "application/json",
        "api-key": "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"
    }
    data = {
        "sender": {"name": "Saksham", "email": "sakshamagrawal310@gmail.com"},
        "to": [{"email": rec}],
        "subject": "Two Factor Authentication Code",
        "htmlContent": "<p>The two step verification code is :</p>"+ str(ver)
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        print('Email sent!')
    else:
        print('Failed to send email')


# Function to get the user's user agent string
def get_user_agent():
    return request.headers.get('User-Agent')

def parse_useragent(user_agent_string):
    user_agent = parse(user_agent_string)
    device_type = user_agent.device.family
    os_name = user_agent.os.family
    os_version = user_agent.os.version_string
    browser_name = user_agent.browser.family
    browser_version = user_agent.browser.version_string
    temp=browser_name+" "+browser_version
    temp1=os_name+" "+os_version
    return temp,temp1,device_type

def break_ip(ip):
    parts = ip.split('.')
    return pd.Series([int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])])

def load_picklefile():
    file=open('browsernameversion_encoder.pkl','rb')
    browsernameversion=pickle.load(file)
    file.close()
    file=open('Country_encoder.pkl','rb')
    countryencoder=pickle.load(file)
    file.close()
    file=open('decision_tree_classifier_20170212.pkl','rb')
    decisiontreeclassifier=pickle.load(file)
    file.close()
    file=open('Devicetype_encoder.pkl','rb')
    devicetyprencoder=pickle.load(file)
    file.close()
    file=open('isattackip_encoder.pkl','rb')
    isattackencoder=pickle.load(file)
    file.close()
    file=open('loginencoder.pkl','rb')
    loginencoder=pickle.load(file)
    file.close()
    file=open('loginsuccessful_encoder.pkl','rb')
    loginsuccessfulencoder=pickle.load(file)
    file.close()
    file=open('OSnameandversion_encoder.pkl','rb')
    osnameversionencoder=pickle.load(file)
    file.close()
    return [browsernameversion,countryencoder,decisiontreeclassifier,devicetyprencoder,isattackencoder,loginencoder,loginsuccessfulencoder,osnameversionencoder]
    
def getdataframe(timestamp,ip,country,asn,browsername,osname,devicetype,loginsuccessfull):
    listofencoders=load_picklefile()
    encoder=listofencoders[1]
    loginencoder=listofencoders[5]
    le=listofencoders[3]
    le1=listofencoders[7]
    le2=listofencoders[6]
    le9=listofencoders[0]
    pattern = r"\d\.*"
    replacement = ""
    lis=['Login Timestamp','IP Address','Country','ASN', 'Browser Name and Version', 'OS Name and Version', 'Device Type', 'Login Successful']
    # data=[['2020-03-30 10:36:08.008'],['83.143.117.213'],['US'],[3938],['Android 2.3.3.2672'],['iOS 7.1'],['mobile'],[True]]
    data=[[timestamp],[ip],[country],[asn],[browsername],[osname],[devicetype],[loginsuccessfull]]
    print(data)
    df1 = pd.DataFrame(dict(zip(lis, data)))
    df1['Login Timestamp'] = df1['Login Timestamp'].apply(convertToSeconds)
    df1[['part1', 'part2', 'part3', 'part4']] = df1['IP Address'].apply(break_ip)
    df1['Browser Name and Version'] = df1['Browser Name and Version'].apply(lambda x: re.sub(pattern, replacement, x))
    df1['OS Name and Version'] = df1['OS Name and Version'].apply(lambda x: re.sub(pattern, replacement, x))
    df1 = pd.concat([df1,encoder.transform(df1['Country'])],axis=1)
    df1.drop('Country',axis=1,inplace=True)
    df1 = pd.concat([df1,loginencoder.transform(df1['Login Timestamp'])],axis=1)
    df1.drop('Login Timestamp', axis=1, inplace=True)
    df1 = pd.concat([df1,le.transform(df1['Device Type'])],axis=1)
    df1.drop('Device Type', axis=1, inplace=True)
    df1 = pd.concat([df1,le1.transform(df1['OS Name and Version'])],axis=1)
    df1.drop('OS Name and Version',axis=1,inplace=True)
    df1['Login Successful']=le2.transform(df1['Login Successful'])
    df1 = pd.concat([df1,le9.transform(df1['Browser Name and Version'])],axis=1)
    df1.drop('Browser Name and Version',axis=1,inplace=True)
    df1.drop('IP Address',axis=1,inplace=True)
    return df1
    
    
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method=='GET':
        session.clear()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email not in users:
            error = 'Invalid credentials. Please try again.'
        elif password != users[email]['password']:
            error = 'Invalid credentials. Please try again.'
        else:
            # Store the user details in the session
            session['email'] = email
            session['name'] = users[email]['name']
            ip=get_ip()
            session['ip_address'] = ip
            print(ip)
            session['user_agent'] = get_user_agent()
            lastlogin=datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S.%f')
            session['last_login'] = lastlogin
            verification_code = random.randint(100000, 999999)
            session['verification_code']=verification_code
            listofasnandcountrycode=getasn_fromip(session['ip_address'])
            browsername,osname,devicetype=parse_useragent(session['user_agent'])
            dataframe=getdataframe(asn=listofasnandcountrycode[0],browsername=browsername,country=listofasnandcountrycode[1],devicetype=devicetype,ip=ip,loginsuccessfull=True,osname=osname,timestamp=lastlogin)
            model=load_picklefile()[2]
            risk=model.predict(dataframe)
            if risk[0]==0:
                session['logged_in']=True
                return redirect('/dashboard')
            else:
                #send_email(session.get('verification_code'),session.get('email'))
                session['logged_in']=False
                return redirect('/twofactor')
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'email' not in session:
        return redirect('/')
    # Get the user details from the session
    if session.get('logged_in')==True:
        email = session['email']
        name = session['name']
        ip_address = session['ip_address']
        user_agent = session['user_agent']
        last_login = session.get('last_login')
        return render_template('dashboard.html', email=email, name=name, ip_address=ip_address, user_agent=user_agent, last_login=last_login)
    else:
        return redirect('/')


@app.route('/twofactor')
def twofactor():
    if 'email' not in session:
        return redirect('/')
    else:
        print(session['verification_code'])
        return render_template('verify2fa.html')
    
    
@app.route('/verify',methods=['POST'])
def verify():
    if 'email' not in session:
        return redirect('/')
    if request.method=='POST':
        user_code = request.form['code']
        temp=session['verification_code']
        print(int(user_code)==temp)
        if int(user_code) == session['verification_code']:
            session['logged_in']=True
            return redirect('/dashboard')
        else:
            return redirect('/')
        
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)