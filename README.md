# log4j
Script checks provided domains for log4j vulnerability.
A token is created with canarytokens.org and passed as header at request for a single domain.
Every token is registered with provided email and the specific domain as note.
After the script completes check your email inbox for mails from canarytokens
IMPORTANT: have to be used with python3
USAGE: 
    - python3 checkLog4J.py --filepath <filepath> --email <email>
REQUIREMENTS: 
    - requests
