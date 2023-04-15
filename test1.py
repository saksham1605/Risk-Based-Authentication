import requests
import random
from bs4 import BeautifulSoup

# open file with proxy list
with open('proxy-list.txt', 'r') as f:
    proxies = [line.strip() for line in f]

# website url to visit
url = 'https://riskbasedauthentication.onrender.com'

for proxy in proxies:
    try:
        email = "john@example.com"
        password = "password123"
        data = {"email": email, "password": password}
        prox = {'http': proxy, 'https': proxy}
        response = requests.post(url, data=data, proxies=prox)
        html = response.text
        # print the formatted HTML
        print(BeautifulSoup(html, 'html.parser').prettify())
    except:
        print()

