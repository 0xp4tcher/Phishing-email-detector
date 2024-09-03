import re
import requests
from email import message_from_file
from email.utils import parseaddr
from bs4 import BeautifulSoup
import spf
from dkim import DKIM
from dmarc import DMARC

def load_email(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return message_from_file(file)

def check_sender_email(email_message, legitimate_domain):
    # Sender's Email Address
    sender_email = parseaddr(email_message.get('From'))[1]
    if legitimate_domain not in sender_email:
        return 20
    return 0

def check_display_name(email_message, organization_pattern):
    # Display Name Mismatch
    display_name = email_message.get('From').split('<')[0].strip()
    if not organization_pattern.match(display_name):
        return 20
    return 0


def check_domain_reputation(sender_domain):
    # Domain Reputation
    blacklist_urls =blacklist_urls = ['https://easydmarc.com/tools/ip-domain-reputation-check',
    'https://www.spamhaus.org/query/domain/',  # Spamhaus Domain Block List (DBL)
    'https://www.abuseipdb.com/check/',        # AbuseIPDB
    'https://www.urlvoid.com/scan/',           # URLVoid
    'https://www.virustotal.com/gui/domain/',  # VirusTotal Domain Report
    'https://www.talosintelligence.com/reputation_center/lookup',  # Cisco Talos Intelligence
    'https://www.fortiguard.com/webfilter?',   # FortiGuard Web Filter
    'https://www.threatcrowd.org/domain.php?',  # ThreatCrowd
    'https://www.malwaredomainlist.com/mdl.php?',  # Malware Domain List (MDL)
    'https://www.phishtank.com/developer_info.php',  # PhishTank Developer API
    'https://www.stopforumspam.com/search?',  # Stop Forum Spam
    'https://exchange.xforce.ibmcloud.com/url/',  # IBM X-Force Exchange
    'https://www.projecthoneypot.org/ip_',  # Project Honey Pot
    'https://checkurl.phishtank.com/checkurl/index.php?',  # PhishTank
    'https://www.malwareurl.com/listing-urls.php?',  # MalwareURL
    'https://www.cyberthreatcoalition.org/submit?url=',  # Cyber Threat Coalition
    'https://www.dan.me.uk/torlist/',  # TOR Exit Nodes
    'https://openphish.com/feed.txt',  # OpenPhish
    'https://urlhaus.abuse.ch/downloads/csv/',  # URLhaus
    'https://www.autoshun.org/files/shunlist.csv',  # Emerging Threats - AutoShun
    'https://www.squidblacklist.org/downloads/dg-https.txt',  # Squidblacklist
    'https://www.botvrij.eu/data/ioclist.domain.ascii',  # Botvrij.eu
    'https://www.binarydefense.com/banlist.txt',  # Binary Defense
    'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',  # Ransomware Tracker - Domain Blocklist
    'https://gitlab.com/Kevin-Kennedy/cti/blob/master/cti-threatlist.txt',  # CTI Threatlist
    'https://blocklist.cyberthreatcoalition.org/vetted/domain.txt',  # Vetted Domain Blocklist
    'https://www.badips.com/get/list/any/2',  # BadIPs
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',  # Emerging Threats - Compromised IPs
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts',  # StevenBlack's Hosts
    'https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt',  # Bambenek Consulting - C2 Domains
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts',  # StevenBlack's Hosts - Porn
    'https://threatfeeds.io/sources/tr-anco/',  # Threat Feeds - Anomali
    'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',  # Feodo Tracker - IP Blocklist
    'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1',  # TOR Exit List (Check)
    'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt',  # Ransomware Tracker - URL Blocklist
    'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',  # Feodo Tracker - Recommended IP Blocklist
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',  # SSL Blacklist
    'https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt',  # Ransomware Tracker - Locky C2 Domain Blocklist
    'https://isc.sans.edu/feeds/suspiciousdomains_High.txt',  # SANS Internet Storm Center - High Confidence Domains
    'https://hosts.ubuntu101.co.za',  # Ubuntu101 Hosts
    'https://www.okean.com/threat-list.txt',  # Okean Threat List
    'https://www.dshield.org/feeds/suspiciousdomains_High.txt',  # DShield - High Confidence Domains
    'https://feodotracker.abuse.ch/downloads/ipblocklist_normal.txt',  # Feodo Tracker - Normal IP Blocklist
    'https://secure.jungledisk.com',  # Jungle Disk
    'https://feodotracker.abuse.ch/downloads/ipblocklist_all.txt',  # Feodo Tracker - All IP Blocklist
    'https://badips.com/get/list/any/1',  # BadIPs (Aggressive)
    'https://urlhaus.abuse.ch/downloads/csv_highrisk/',  # URLhaus - High Risk
]
 # Add actual blacklist URLs
    for url in blacklist_urls:
        if requests.get(f"{url}/{sender_domain}").status_code == 200:
            return 20
    return 0

def check_links(email_message):
    # Number and Relevance of Links
    num_links = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_message.get_payload()))
    if num_links > 5 or num_links == 0:
        return 25

    # Domain Reputation of Links
    link_domains = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_message.get_payload())
    for link in link_domains:
        domain = link.split('/')[2]
        if check_domain_reputation(domain):
            return 25

    # Hidden or Shortened URLs
    if re.search(r'http[s]?://short.url', email_message.get_payload()):
        return 25

    return 0
def check_shortened_urls(email_message):
    # Check, expand, and verify shortened URLs
    links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_message.get_payload())
    for link in links:
        expanded_url = requests.head(link, allow_redirects=True).url
        if 'checkshorturl.com' in expanded_url:
            return 25
    return 0

def check_file_maliciousness(email_message):
    # Check if a file attached in an email is malicious using VirusTotal
    for part in email_message.walk():
        if part.get_content_maintype() == 'application' and part.get('Content-Disposition') is not None:
            file_content = part.get_payload(decode=True)
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files={'file': file_content})
            if response.status_code == 200:
                result = response.json()
                if result['positives'] > 0:
                    return 25
    return 0
def check_spf(email_message):
    # SPF Check
    spf_result = spf.check2(ip=email_message.get('Received-SPF'))
    if spf_result == 'pass':
        return 0
    return 15

def check_dkim(email_message):
    # DKIM Check
    dkim_result = email_message.get('DKIM-Signature')
    if dkim_result:
        dkim = DKIM(email_message.as_bytes())
        if dkim.verify():
            return 0
    return 15

def check_dmarc(email_message):
    # DMARC Check
    dmarc_result = email_message.get('Authentication-Results', '').lower()
    if 'spf=pass' in dmarc_result and 'dkim=pass' in dmarc_result:
        return 0
    return 10
# Similar functions for SPF, DKIM, DMARC, Content Analysis, Unusual Sending Behavior, Reply-To Field, and IP Reputation of Sender

def calculate_total_score(scores):
    return sum(scores)

def interpret_score(total_score):
    if total_score <= 20:
        return "Likely Safe"
    elif total_score <= 40:
        return "Low Risk"
    elif total_score <= 70:
        return "Moderate Risk"
    else:
        return "High Risk"

def main():
    eml_file_path =r"C:\Users\0xp4t\tester\sample2.eml"
    legitimate_domain = 'https://www.facebook.com/'
    organization_pattern = re.compile(r'solutionteam-recognizd23hotmail.com', flags=re.I)

    email_message = load_email(eml_file_path)

    scores = [
        check_sender_email(email_message, legitimate_domain),
        check_display_name(email_message, organization_pattern),
        check_domain_reputation('solutionteam-recognizd23hotmail.com'),  # Replace 'sender_domain' with actual domain
        check_links(email_message),
        # Add calls to other functions for SPF, DKIM, DMARC, Content Analysis, Unusual Sending Behavior, Reply-To Field, and IP Reputation of Sender
    ]

    total_score = calculate_total_score(scores)
    interpretation = interpret_score(total_score)

    print(f"Total Score: {total_score}")
    print(f"Interpretation: {interpretation}")

if __name__ == "__main__":
    main()
