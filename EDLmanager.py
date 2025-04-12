import argparse
import datetime
import calendar
import requests
import time
from dotenv import load_dotenv
import os

def abuseIPDB(ip, api_key):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    view_url = f'https://www.abuseipdb.com/check/{ip}'
    headers = {
        "Accept": "application/json",
        "Key": api_key  # AbuseIPDB API Key
    }
    response = requests.get(url, headers=headers)
    print("\n[+] AbuseIPDB scan:\n")
    if response.status_code == 200:
        data = response.json()
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        if abuse_confidence_score > 0:
            print(f'\t. {ip} has an abuse confidence score of {abuse_confidence_score}/100. See {view_url}')
            return True
        else:
            print(f'\t. No abusive activity found for {ip}. See {view_url}')
    else:
        print(f"\tFailed to fetch {ip} data. Status Code: {response.status_code}")
    return False

def vtScan(ioc,type, api):
    if type == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
        view_url = f'https://www.virustotal.com/gui/ip-address/{ioc}'
    elif type == 'domain':
        url = f'https://www.virustotal.com/api/v3/domains/{ioc}'
        view_url = f'https://www.virustotal.com/gui/domain/{ioc}'
    headers = {
        "accept": "application/json",
        "x-apikey": api  # Virustotal API KEY
    }
    response = requests.get(url, headers=headers)
    print(f"\n[+] VirusTotal scan:\n")
    if response.status_code == 200:
        data = response.json()
        attributes = data['data']['attributes']
        last_analysis_date = attributes.get('last_analysis_date')
        last_analysis_stats = attributes.get('last_analysis_stats')
        if last_analysis_date is not None:
            maxdays = 7776000 #90 days in seconds
            # Sum analysis stats /y
            total = sum(last_analysis_stats.values())
                
            # Get malicious stats x/
            malicious = last_analysis_stats['malicious']
            print(f'\t. {malicious}/{total} security vendors flagged {ioc}. See {view_url}') # VirusTotal scan: x/y

            if ((time.time() - last_analysis_date) < maxdays and malicious != 0) or malicious > 4:
                return True
    else:
         print(f"Failed to fetch {ioc} data. Status Code: {response.status_code}")
    return False

def checkIOC(ioc, type, api_abuse, api_vt):
    vt = ab = False
    if type == 'ip':
        vt = vtScan(ioc,'ip',api_vt)
        ab = abuseIPDB(ioc,api_abuse)
    elif type == 'domain':
        vt = vtScan(ioc,'domain',api_vt)
    time.sleep(15) #api limit 4 request per minute
    return vt or ab

def readEDL(file_path):
    edl = {}
    comment = None
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line.startswith("#"):
                comment = line
                if comment not in edl:
                    edl[comment] = []
            elif comment:
                edl[comment].append(line)
    return edl

def writeEDL(file_path, edl):
    with open(file_path, 'w', encoding='utf-8') as file:
        for comment, iocs in edl.items():
            file.write(f'{comment}\n')
            for ioc in iocs:
                file.write(f'{ioc}\n')

def removeIOC(edl_path, ioc):
    edl = readEDL(edl_path)
    comments = list(edl.keys())
    for group in comments:
        ioc_group = edl[group]
        if ioc in ioc_group:
            ioc_group.remove(ioc)
            print(f'[-] {ioc}')
    writeEDL(edl_path, edl)

def cleanEDL(edl_path, type, api_abuse, api_vt):
    edl = readEDL(edl_path)
    comments = list(edl.keys())
    for group in comments:
        ioc_group = edl[group]
        for ioc in ioc_group:
            if not checkIOC(ioc, type, api_abuse, api_vt):
                removeIOC(edl_path, ioc)
                print(f'[x] {ioc} was removed from {edl_path}')

def add2EDL(edl_path, comment_group, new_ioc):
    edl = readEDL(edl_path)
    block = True
    comments = list(edl.keys())
    for group in comments:
        ioc_group = edl[group]
        if new_ioc in ioc_group:
            if comment_group != group:
                ioc_group.remove(new_ioc)
                print(f'[-] {new_ioc}')
            else:
                block = False
        if not ioc_group:
            del edl[group]
            print(f'[-] {group}')      
    
    if comment_group not in edl:
        edl[comment_group] = []
        print(f'[+] {comment_group}')
    
    if block:
        edl[comment_group].append(new_ioc)
        print(f'[+] {new_ioc}')
    writeEDL(edl_path, edl)

def formatMonth():
    today = datetime.datetime.now()
    month = calendar.month_name[today.month]
    year = today.year
    month_pt = {
        'January': 'janeiro',
        'February': 'fevereiro',
        'March': 'março',
        'April': 'abril',
        'May': 'maio',
        'June': 'junho',
        'July': 'julho',
        'August': 'agosto',
        'September': 'setembro',
        'October': 'outubro',
        'November': 'novembro',
        'December': 'dezembro'
    }
    return f'#{month_pt[month]}/{year} - '

def main():
    parser = argparse.ArgumentParser(description='EDL Manager')
    parser.add_argument('-i', '--ip', dest='ip', required=False, help='Add IP to DL-IP-MALICIOUS.txt')
    parser.add_argument('-d', '--domain', dest='domain', required=False, help='Add DOMAIN to DL-DOMAIN-MALICIOUS.txt')
    parser.add_argument('-e', '--email', dest='email', required=False, help='Add EMAIL to DL-EMAIL-MALICIOUS.txt')
    parser.add_argument('-s', '--hash', dest='hash', required=False, help='Add HASH to DL-HASH-MALICIOUS.txt')
    parser.add_argument('-c', '--comment', dest='comment', required=False, help='Add "comment" about the IOC')
    parser.add_argument('-m', '--more', dest='more', required=False, action='store_true', help='Add more IOC')
    parser.add_argument('-r', '--remove', dest='remove', required=False, action='store_true', help='Remove IOC')
    parser.add_argument('-cl', '--cleaner', dest='cleaner', required=False, help='Clear IOCs')
    args = parser.parse_args()

    load_dotenv(override=True)
    #.env file content example:
    #   virustotal_api = "API_KEY"
    #   abuseipdb_api = "API_KEY"

    virustotal_api = os.getenv("virustotal_api")
    abuseipdb_api = os.getenv("abuseipdb_api")

    data = None

    arg_map = {
        'ip': ('ip', 'DL-IP-MALICIOUS.txt'),
        'domain': ('domain', 'DL-DOMAIN-MALICIOUS.txt'),
        'email': ('email', 'DL-EMAIL-MALICIOUS.txt'),
        'hash': ('hash', 'DL-HASH-MALICIOUS.txt'),
    }

    if args.cleaner:
        for key, (ioc_type, file_path) in arg_map.items():
            if args.cleaner == key and (key == ('ip' or 'domain')):
                cleanEDL(file_path, ioc_type, abuseipdb_api, virustotal_api)
                return
        parser.error("To use --cleaner, specify one of the following: -cl ip or -cl domain to indicate the IOC type to clear.")
       
    if not any(getattr(args, arg) for arg in arg_map):
        parser.error('You must provide one of the following: -i, -d, -e, or -s, along with -c (comment) or -r (remove).')
    
    for arg, (ioc_type, file_path) in arg_map.items():
        if getattr(args, arg):
            data = getattr(args, arg)
            iocs = [data]

            if args.more:
                print(f'Enter multiple {ioc_type.upper()}s, one per line. Press ENTER to finish:')
                while True:
                    entry = input()
                    if not entry:
                        break
                    iocs.append(entry)

            for ioc in iocs:
                if args.remove:
                    removeIOC(file_path, ioc)
                elif args.comment:
                    comment = formatMonth() + args.comment
                    add2EDL(file_path, comment, ioc)
                else:
                    print("Missing argument: use -c to add or -r to remove.")
            break

if __name__ == "__main__":
    main()