import re
import urllib3
import unicodedata
import idna
import socket
import logging
from bs4 import BeautifulSoup
from email_validator import validate_email, EmailNotValidError
import constants

# Create a custom logger
logger = logging.getLogger(__name__)

def normalize(input_string):
    return unicodedata.normalize('NFC',input_string)

def validateDomainName(domain_name):
    domain_name = domain_name.split('/')[0]
    try:
        domainName_normalized = normalize(domain_name) #normalize to NFC        
        #U-label to A-label
        domainName_alabel = idna.encode(domainName_normalized).decode("ascii") #U-label to A-label
        return domainName_alabel
    except idna.IDNAError as e:
        print(f"Domain '{domain_name}' is invalid: {e}")  #invalid domain as per IDNA 2008
        return None
    except Exception as e:
        print(f"ERROR: {e}")
        return None

def resolveDomainName(domain_name):
    try:
        #get IP address of the domain
        ip = socket.gethostbyname(domain_name)
        print(ip)
    except idna.IDNAError as e:
        print(f"Domain '{domain_name}' is invalid: {e}")  #invalid domain as per IDNA 2008
    except Exception as e:
        print(f"ERROR: {e}")

#function to convert convert U-label to A-label and changing arabic digits to ascii
def convertEmailAddress(domain_name, mailbox_name):
    return '@'.join((mailbox_name, idna.encode(domain_name).decode('ascii')))

def formatEmail(email):
    mailbox_name, domain_name = email.rsplit('@', 1)
    domain_normalized= normalize(domain_name)#normalize domain name
    try:
        updated_email = convertEmailAddress(domain_normalized, mailbox_name)
        # validated = validate_email(updated_email, check_deliverability=True)
        return updated_email
    except EmailNotValidError as e:
        return None
    except Exception as ex:
        return None

http = urllib3.PoolManager()

res = http.request('GET', 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
res = res.data.decode("utf-8") 
tlds = res.split('\n')

# removing first and last elements
tlds = tlds[1:-1]

domains = []
for tld in tlds:
    domains.append('.' + tld.lower())

with open(constants.INPUT_FILE, 'r', encoding='UTF-8') as f:
    html = f.read()

soup = BeautifulSoup(html, 'html.parser')
        
# soup = BeautifulSoup(html, 'html.parser')

for domain in domains:
    pattern = fr"\S+{re.escape(domain)}(?=\W|$)\S*"
    for tag in soup.find_all(string=re.compile(pattern)):
        if tag.parent.name in ['a', 'script', 'style']:
            continue
        text = tag.string
        if text is None:
            continue
        matches = re.finditer(pattern, text)
        text_len = len(text)
        new_text_len = text_len

        for match in matches:
            len_diff = new_text_len - text_len
            start_index = match.start() + len_diff
            end_index = match.end() +len_diff
            matched_string = text[start_index :end_index]

            replacement = matched_string
            if '@' in matched_string:
                v = formatEmail(matched_string)
                if v != None:
                    replacement = f'<a target="_blank" href="mailto:{v}">{matched_string}</a>'
            else:
                if "https" in matched_string:
                    v = validateDomainName(matched_string[8:])
                    if v != None:
                        replacement = f'<a target="_blank" href="https://{v}">{matched_string}</a>'
                elif "http" in matched_string:
                    v = validateDomainName(matched_string[7:])
                    if v != None:
                        replacement = f'<a target="_blank" href="http://{v}">{matched_string}</a>'
                else:
                    v = validateDomainName(matched_string)
                    if v != None:
                        replacement = f'<a target="_blank" href="https://{v}">{matched_string}</a>'

            new_text = text[:start_index] + replacement + text[end_index:]
            new_text_len = len(new_text)
            text = new_text
            update_tag_string = BeautifulSoup(text, features='html.parser')
        tag.replace_with(update_tag_string)

        
special_pattern = r"\S+\.\S+"
special_domains = soup.find_all(string=re.compile(special_pattern))
for s_domain in special_domains:
    matches = re.finditer(special_pattern, s_domain)
    text_len = len(s_domain)
    new_text_len = text_len
    update_tag_string = ""
    for match in matches:
        len_diff = new_text_len - text_len
        start_index = match.start() + len_diff
        end_index = match.end() +len_diff
        matched_string = s_domain[start_index :end_index]
        exp = re.search(r'[^\x00-\x7f]+', matched_string)
        if exp != None:
            # print(matched_string)
            replacement = matched_string
            
            if '@' in matched_string:
                v = formatEmail(matched_string)
                # v = None
                if v != None:
                    replacement = f'<a target="_blank" href="mailto:{v}">{matched_string}</a>'
            else:
                if "https" in matched_string:
                    v = validateDomainName(matched_string[8:])
                    if v != None:
                        replacement = f'<a target="_blank" href="https://{v}">{matched_string}</a>'
                elif "http" in matched_string:
                    v = validateDomainName(matched_string[7:])
                    if v != None:
                        replacement = f'<a target="_blank" href="http://{v}">{matched_string}</a>'
                else:
                    v = validateDomainName(matched_string)
                    if v != None:
                        replacement = f'<a target="_blank" href="https://{v}">{matched_string}</a>'

            # new_text = matched_string[:start_index] + replacement + matched_string[end_index:]
            new_text = replacement
            # matched_string = new_text
            update_tag_string = BeautifulSoup(new_text, features='html.parser')
            soup = str(soup).replace(matched_string, new_text)

with open(constants.OUTPUT_FILE, "w", encoding='UTF-8') as f:
    f.write(str(soup))
