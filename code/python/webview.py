from flask import Flask, render_template, request, jsonify, send_file
from bs4 import BeautifulSoup
import aiohttp
import json as jn
import asyncio
import src.sqllite_db as sdb
import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
sites_db = sdb.DataBase("../../assets/databases/ip_addrs.sql")
ips_db   = sdb.DataBase("../../assets/databases/ip_info_addrs.sql")
analys_db = sdb.DataBase("../../assets/databases/vuln_ips.sql")

def is_ip(string: str):
    dot_count = string.count(".")
    if dot_count != 3: return False
    hexlets = string.split('.')
    for hexl in hexlets:
        if not hexl.isalnum():
            return False
    
    return True

def get_site_text(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    paragraphs = soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'title'])
    text = ' '.join([tag.get_text(strip=True) for tag in paragraphs])
    return text

"""
inurl: https://
incontent: Hello world!
intitle: how-to
indomain: org

ipfrom: US
ipcity: New York
ippostal: 10001
iporg: Google
iplang: en-GB

ippat: 96.12.*.12-96

(pattern AND pattern) - a and b
(pattern OR pattern)  - a or b
-pattern              - not a

"""

async def get_ip_info(ip: str):
    url = f"https://ipapi.co/{ip}/json/"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as response:
                text = await response.text()
                print(text)
                result = jn.loads(text)
                return {
                    "from": result['country_name'],
                    "city": result['city'],
                    "postal": result['postal'],
                    "org": result['org'],
                    "languages": result['languages'].split(','),
                    "ip": ip
                }
        except:
            return { "from": "", "city": "", "postal": "", "org": "", "languages": "", "ip": ip }

def get_parenthesis_pair(parenthesis: str) -> tuple[str, str]:
    if parenthesis == "(" or parenthesis == ")":
        return ("(", ")")
    elif parenthesis == "[" or parenthesis == "]":
        return ("[", "]")
    elif parenthesis == "{" or parenthesis == "}":
        return ("{", "}")
    return ("", "")

def parse_parenthesis_pair(text: str, parenthesis: str) -> tuple[str, int, str]:
    parenthesis_pair = get_parenthesis_pair(parenthesis)

    fi = text.index(parenthesis_pair[0]) + len(parenthesis_pair[0])
    si = text.index(parenthesis_pair[1], fi)

    ans = text[fi:si]
    return ans, text[si+1:]

def process_by_dorks(search_string: str, ip: str | None, domain: str | None, content: str | None, title: str | None) -> bool:
    def in_url_dork(strg: str) -> bool:
        if strg.startswith("inurl:"):
            return strg[6:].strip() in search_string
        return False
    
    def in_content_dork(strg: str) -> bool:
        if strg.startswith("incontent:"):
            return strg[10:].strip() in search_string
        return False
    
    def in_title_dork(strg: str) -> bool:
        if strg.startswith("intitle:"):
            return strg[7:].strip() in search_string
        return False
    
    def in_domain_dork(strg: str) -> bool:
        if strg.startswith("indomain:"):
            return strg[8:].strip() in search_string
        return False
    
    def ip_from_dork(strg: str, ip_info: dict[str, str]) -> bool:
        if strg.startswith("ipfrom:"):
            return strg[7:].strip() == ip_info['from']
        return False
    
    def ip_city_dork(strg: str, ip_info: dict[str, str]) -> bool:
        if strg.startswith("ipcity:"):
            return strg[7:].strip() == ip_info['city']
        return False
    
    def ip_postal_dork(strg: str, ip_info: dict[str, str]) -> bool:
        if strg.startswith("ippostal:"):
            return strg[9:].strip() == ip_info['postal']
        return False
    
    def ip_org_dork(strg: str, ip_info: dict[str, str]) -> bool:
        if strg.startswith("iporg:"):
            return strg[6:].strip() == ip_info['org']
        return False
    
    def ip_langauge_dork(strg: str, ip_info: dict[str, str]) -> bool:
        if strg.startswith("iplang:"):
            return strg[7:].strip() in ip_info['langauge']
        return False
    
    def ip_pattern_dork(strg: str, ip_info: dict[str, str]) -> bool:
        if strg.startswith("ippat:"):
            tar_ip = strg[6:].strip().split('.')
            inf_ip = ip_info['ip'].split('.')
            for decl, inf_decl in zip(tar_ip, inf_ip):
                if decl == '*':
                    continue
                if '-' in decl:
                    start, end = decl.split('-')
                    if not (int(start) <= int(inf_decl) <= int(end)):
                        return False
                    continue
                if decl != inf_decl:
                    return False
            return True
        return False

    dorks = {}
    res, next_ = parse_parenthesis_pair(search_string, '(')
    while len(next_) != 0:
        res, next_ = parse_parenthesis_pair(next_, '(')

def search_database(
    title_search: str | None = None,
    content_search: str | None = None,
    real_search: str | None = None,
    domain_search: str | None = None,
    ip_search: str | None = None
) -> tuple[list[str], list[str]]:
    
    if title_search == content_search == domain_search == ip_search == None:
        return []

    big_data = sites_db.all()
    all_ips = set()

    for ip in big_data:
        # print(ip, ip_search)
        data = sites_db.get(ip)
        content = data["content"]
        real_content = data.get("real-content", "")
        ip_info = data.get("ip-info", { "from": "", "city": "", "postal": "", "org": "", "languages": "", "ip": ip })
        domain = data["domain"]
        title = data["title"]

        if title_search and (title_search in title):       all_ips.add(ip)
        if content_search and (content_search in content): all_ips.add(ip)
        if domain_search and (domain_search in domain):    all_ips.add(ip)
        if ip_search and (ip_search in ip):                all_ips.add(ip)
        if real_search and (real_search in real_content):  all_ips.add(ip)

    return list(), list(all_ips)

def get_link(
    ip_addr: str,
    has_https: bool
):
    if has_https:
        ip_addr = "https://" + ip_addr
    else:
        ip_addr = "http://" + ip_addr

    return ip_addr

async def fetch_content(session, ip_addr, has_https):
    ip_addr = get_link(ip_addr, has_https)
    try:
        async with session.get(ip_addr, timeout=5) as response:
            if response.status == 200:
                content = await response.text()
                return response.status, content
            return response.status, ""
    except:
        return 404, ""

async def new_ip_addr(ip_addr: str, domain: str, has_https: bool):
    title = ""
    content = ""

    async with aiohttp.ClientSession() as session:
        status, content = await fetch_content(session, ip_addr, has_https)
        if status == 200 and "<title>" in content:
            title = content[
                content.find("<title>")+len("<title>"):
                content.find("</title>")
            ]

    if is_ip(ip_addr):
        return (
            ip_addr, {
                "content": content,
                "title": title,
                "domain": domain,
                "has-https": has_https,
                "real-content": get_site_text(content),
                # "ip-info": await get_ip_info(ip_addr)
            }
        )
    else:
        print(f"not an IP {ip_addr}")
        return None

@app.route('/database')
def database_download():
    return send_file('../../assets/databases/ip_addrs.sql')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    data = request.get_json()
    input_value = data.get('input')
    searches = data.get("searches")
    print(searches)
    results, all_ips = search_database(
        title_search=input_value if searches["title"] else None,
        domain_search=input_value if searches["domain"] else None,
        content_search=input_value if searches["content"] else None,
        ip_search=input_value if searches["ip"] else None
    )

    return jsonify({
        "results": [{
            "title": sites_db.get(ip)["title"] if len(sites_db.get(ip)["title"]) != 0 else f"[domain] {sites_db.get(ip)["domain"]}", 
            "snippet": get_site_text(sites_db.get(ip)["content"])[:100],
            "url": get_link(ip, sites_db.get(ip)["has-https"])
        } for ip in all_ips]
    })

@app.route('/new_ip', methods=['POST'])
async def registrate_new_ip():
    big_data = request.get_data(as_text=True)
    print(f"[API] New IPs are getting from {request.remote_addr} ({len(big_data.splitlines())})")
    batch = []
    tasks = []

    for raw_data in big_data.splitlines():
        raw_data = raw_data.split()
        try:
            ip = raw_data[0]
            domain = raw_data[1]
            has_https = raw_data[2] == 'true'
        except:
            print(f"Skipping {raw_data}")
            continue

        data = {
            "ip": ip,
            "domain": domain,
            "has-https": has_https
        }
        print(f"New site {data['ip']}")
        if not is_ip(data["ip"]):
            print(f"From {request.remote_addr} ->\n{'-'*10}\n{data['ip']}\n{'-'*10}\n\n is not IP")
            continue
        tasks.append(new_ip_addr(data["ip"], data["domain"] if data["domain"] != "__empty" else "", data["has-https"]))

    results = await asyncio.gather(*tasks)
    for res in results:
        if res:
            batch.append(res)

    sites_db.batch_set(batch)
    return "ok"

if __name__ == '__main__':
    # print(get_site_text(requests.get("https://google.com").text))
    app.run(
        host="192.168.31.100",
        port=8080,
        # debug=True
    )
    # sites_db.close()