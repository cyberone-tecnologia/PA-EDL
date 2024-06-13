import argparse

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
            file.write(f'\n{comment}')
            for ioc in iocs:
                file.write(f'\n{ioc}')

def add2EDL(edl_path, comment, ioc):
    lines = readEDL(edl_path)
    print("~ History:")
    comment_to_remove = []
    for key in lines:
        value = lines[key]
        if ioc in value:
            value.remove(ioc)
            print(f'[-] {ioc}')
        if not value:
            comment_to_remove.append(key)
            print(f'[-] {key}')
    for key in comment_to_remove:
        del lines[key]
    
    if comment not in lines:
        lines[comment] = []
        print(f'[+] {comment}')
    lines[comment].append(ioc)
    print(f'[+] {ioc}')
    writeEDL(edl_path, lines)

def menu():
    parser = argparse.ArgumentParser(description='EDL Manager')
    parser.add_argument('-i', '--ip', dest='ip', required=False, help='Add IP to DL-IP-MALICIOUS.txt')
    parser.add_argument('-d', '--domain', dest='domain', required=False, help='Add DOMAIN to DL-DOMAIN-MALICIOUS.txt')
    parser.add_argument('-e', '--email', dest='email', required=False, help='Add EMAIL to DL-EMAIL-MALICIOUS.txt')
    parser.add_argument('-s', '--hash', dest='hash', required=False, help='Add HASH to DL-HASH-MALICIOUS.txt')
    parser.add_argument('-c', '--comment', dest='comment', required=True, help='Add "comment" about the IOC')
    args = parser.parse_args()

    data = None
    option = None

    if args.ip:
        data = args.ip
        option = 'DL-IP-MALICIOUS.txt'
    elif args.domain:
        data = args.domain
        option = 'DL-DOMAIN-MALICIOUS.txt'
    elif args.email:
        data = args.email
        option = 'DL-EMAIL-MALICIOUS.txt'
    elif args.hash:
        data = args.hash
        option = 'DL-HASH-MALICIOS.txt'
    else:
        parser.error('At least one of the options -i, -d, -e, or -s must be provided along with -c')
    
    return option, args.comment, data

def main():
    option, comment, data = menu()
    if option:
        add2EDL(option, comment, data)

if __name__ == "__main__":
    main()