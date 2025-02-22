from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
import requests
import src.easy_db as db
import src.sqllite_db as sdb
import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# sites_db = db.DataBase("../../assets/databases/ip_addrs.json")
sites_db = sdb.DataBase("../../assets/databases/ip_addrs.sql")

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
    
    # Извлекаем текст только из нужных тегов
    paragraphs = soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a'])
    text = ' '.join([tag.get_text(strip=True) for tag in paragraphs])
    
    return text

def search_database(
    title_search: str | None = None,
    content_search: str | None = None,
    domain_search: str | None = None,
    ip_search: str | None = None
) -> tuple[list[str], list[str]]:
    
    if title_search == content_search == domain_search == ip_search == None:
        return []

    big_data = sites_db.all()
    print(big_data)
    all_ips = set()

    for ip, data in big_data.items():
        print(ip, ip_search)
        content = data["content"]
        domain = data["domain"]
        title = data["title"]

        if title_search and (title_search in title):
            # title_results.add(ip)
            all_ips.add(ip)
        
        if content_search and (content_search in content):
            # content_results.add(ip)
            all_ips.add(ip)

        if domain_search and (domain_search in domain):
            # domain_results.add(ip)
            all_ips.add(ip)
        
        if ip_search and (ip_search in ip):
            # ip_results.add(ip)
            all_ips.add(ip)
    
    # to_intersect: list[set] = []
    # if not (title_search is None):   to_intersect.append(title_results)
    # if not (content_search is None): to_intersect.append(content_results)
    # if not (domain_search is None):   to_intersect.append(domain_results)
    # if not (ip_search is None):      to_intersect.append(ip_results)

    # answer = set()
    # curr_set = to_intersect[0]

    # if len(to_intersect) == 1:
    #     answer.union(curr_set)

    # if len(to_intersect) == 2:
    #     answer = curr_set.intersection(
    #         to_intersect[i+1]
    #     )

    # for i in range(max(0, len(to_intersect) - 2)):
    #     answer = answer.intersection(
    #         to_intersect[i+1]
        # )
    
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

def get_content(
    ip_addr: str,
    has_https: bool
):
    ip_addr = get_link(ip_addr, has_https)

    try:
        req = requests.get(ip_addr, verify=False, timeout=5)
        content = ""
        if req.status_code == 200:
            content = req.text
        
        return req.status_code, content
    except:
        return 404, ""

def new_ip_addr(
    ip_addr: str,
    domain:   str,
    has_https: bool
):
    title = ""
    content = ""

    # req = requests.get(ip_addr)
    status, content = get_content(ip_addr, has_https)
    if status == 200:
        if content.count("<title>") != 0:
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
                "has-https": has_https
            }
        )
    else:
        print(f"not an IP {ip_addr}")
        return None

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
    print(f"Search result ({input_value}): {all_ips}")

    return jsonify({
        "results": [{
            "title": sites_db.get(ip)["title"] if len(sites_db.get(ip)["title"]) != 0 else f"[domain] {sites_db.get(ip)["domain"]}", 
            "snippet": get_site_text(sites_db.get(ip)["content"])[:100],
            "url": get_link(ip, sites_db.get(ip)["has-https"])
        } for ip in all_ips]
    })

@app.route('/new_ip', methods=['POST'])
def registrate_new_ip():
    big_data = request.get_data(as_text=True)
    print(big_data)
    batch = []
    for raw_data in big_data.splitlines():
        raw_data = raw_data.split()
        data = {
            "ip": raw_data[0],
            "domain": raw_data[1],
            "has-https": raw_data[2] == 'true'
        }
        print(data)
        if not is_ip(data["ip"]):
            print(f"From {request.remote_addr} ->\n{'-'*10}\n{data["ip"]}\n{'-'*10}\n\n is not IP")
            continue
            # return "fail"
        res = new_ip_addr(
            data["ip"],
            data["domain"] if data["domain"] != "__empty" else "",
            data["has-https"]
        )
        if res:
            batch.append(res)
    
    sites_db.batch_set(batch)

    print("Returning..")
    return "ok"

if __name__ == '__main__':
    # print(get_site_text(requests.get("https://google.com").text))
    app.run(
        host="192.168.31.100",
        port=8080,
        # debug=True
    )
    # sites_db.close()