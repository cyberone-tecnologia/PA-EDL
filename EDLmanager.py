import argparse
import datetime
import calendar

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

def menu():
    parser = argparse.ArgumentParser(description='EDL Manager')
    parser.add_argument('-i', '--ip', dest='ip', required=False, help='Add IP to DL-IP-MALICIOUS.txt')
    parser.add_argument('-d', '--domain', dest='domain', required=False, help='Add DOMAIN to DL-DOMAIN-MALICIOUS.txt')
    parser.add_argument('-e', '--email', dest='email', required=False, help='Add EMAIL to DL-EMAIL-MALICIOUS.txt')
    parser.add_argument('-s', '--hash', dest='hash', required=False, help='Add HASH to DL-HASH-MALICIOUS.txt')
    parser.add_argument('-c', '--comment', dest='comment', required=True, help='Add "comment" about the IOC')
    parser.add_argument('-m', '--more', dest='more', required=False, action='store_true', help='Add more IOC')
    args = parser.parse_args()

    data = None
    option = None
    bulk = []

    arg_map = {
        'ip': ('Insert an IP (or press Enter to leave): ', 'DL-IP-MALICIOUS.txt'),
        'domain': ('Insert a DOMAIN (or press Enter to leave): ', 'DL-DOMAIN-MALICIOUS.txt'),
        'email': ('Insert a EMAIL (or press Enter to leave): ', 'DL-EMAIL-MALICIOUS.txt'),
        'hash': ('Insert a HASH (or press Enter to leave): ', 'DL-HASH-MALICIOUS.txt')
    }

    if not any(getattr(args, arg) for arg in arg_map.keys()):
        parser.error('One of the options -i, -d, -e, or -s must be provided along with -m or -c')
    
    for arg, (message, file_option) in arg_map.items():
        if getattr(args, arg):
            print(message)
            data = getattr(args, arg)
            if args.more:
                bulk.append(data)
                print(data)
            option = file_option
            break
        
    if args.more:
        while True:
            data = input()
            if data:
                bulk.append(data)
            else:
                break
    
    comment = formatMonth() + args.comment
    return option, comment, data, bulk

def main():
    option, comment, data, bulk = menu()
    print("~ History:")
    if bulk:
        for ioc in bulk:
            add2EDL(option, comment, ioc)
    elif option:
        add2EDL(option, comment, data)

if __name__ == "__main__":
    main()