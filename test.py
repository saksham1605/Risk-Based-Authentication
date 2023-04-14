# import requests

# # Make a request to the IPinfo.io API to get ASN information for an IP address
# ip_address = '8.8.8.8'
# response = requests.get(f'https://ipinfo.io/{ip_address}/org')

# # Extract the ASN number from the API response
# asn_number = response.text.split()[0][2:]

# print(f'The ASN number for {ip_address} is {asn_number}')
# def parse_useragent(user_agent_string):
#     user_agent = parse(user_agent_string)
#     device_type = user_agent.device.family
#     os_name = user_agent.os.family
#     os_version = user_agent.os.version_string
#     browser_name = user_agent.browser.family
#     browser_version = user_agent.browser.version_string
#     temp=browser_name+" "+browser_version
#     temp1=os_name+" "+os_version
#     print(temp,temp1,device_type)
# parse_useragent()

# import re

# string = "Firefox 20.0.0.1843"
# pattern = r"\d\.*"
# replacement = ""

# new_string = re.sub(pattern, replacement, string)

# print(new_string)

import geoip2.database

# Load the GeoLite2 database
reader = geoip2.database.Reader('GeoLite2-Country_20230414/GeoLite2-Country.mmdb')
response = reader.country('103.21.124.77')
print(response.country.iso_code)
reader = geoip2.database.Reader('GeoLite2-ASN_20230414/GeoLite2-ASN.mmdb')
response = reader.asn('103.21.124.77')
print(response.autonomous_system_number)

