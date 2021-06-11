
# Parse Godaddy Apache Logs and reverse geocode IP addresses
# apachelogs to parse
# ipstack to reverse geocode
# Keep counts of dupicate IP addresses

import re
import json
from ipstack import GeoLookup
import apachelogs
from apachelogs import LogParser


# unknown godaddy trailing field
exclude_field = "\s\*+\d+/\d+\*+"
log_records = []
log_name = 'access_log'

# standardize apache logfile records (remove godaddy trailing field)
with open(log_name, 'r') as file:
    log = file.readlines()
    for record in log:
        # exclude last field from godaddy logs that isn't apache
        log_records.append(re.sub(exclude_field, '', record))

# Search to see if IP already in dict


def search(hosts, ip):
    return [element for element in hosts if element['ip'] == ip]

# What is the index of list if ip key exists


def index(hosts, ip):
    return next((index for (index, d) in enumerate(hosts) if d['ip'] == ip), None)


# Parse log records and take the IP and increment count for dups


parser = LogParser(apachelogs.COMBINED)
hosts = []
# ipstack access key
geo_lookup = GeoLookup("API Key")

for rec in log_records:
    entry = parser.parse(rec)
    ip = entry.remote_host

    if not search(hosts, ip):
        # new dict to add to hosts list
        location = geo_lookup.get_location(ip)
        location['count'] = 1
        hosts.append(location)
    else:
        idx = index(hosts, ip)
        hosts[idx]['count'] += 1

# Write data out as an list of dicts  
with open("access_log.json", 'w') as outfile:
    outfile.write(json.dumps(hosts))
    
    
    
 '''
 Sample output
 [
    {'ip': '141.94.20.52', 'type': 'ipv4', 'continent_code': 'EU', 'continent_name': 'Europe', 'country_code': 'DE', 'country_name': 'Germany', 'region_code': None, 'region_name': None, 'city': None, 'zip': None, 'latitude': 51, 'longitude': 9, 'location': {'geoname_id': None, 'capital': 'Berlin', 'languages': [{'code': 'de', 'name': 'German', 'native': 'Deutsch'}], 'country_flag': 'http://assets.ipstack.com/flags/de.svg', 'country_flag_emoji': '🇩🇪', 'country_flag_emoji_unicode': 'U+1F1E9 U+1F1EA', 'calling_code': '49', 'is_eu': True}, 'count': 1}, 
    {'ip': '54.191.137.17', 'type': 'ipv4', 'continent_code': 'NA', 'continent_name': 'North America', 'country_code': 'US', 'country_name': 'United States', 'region_code': 'OR', 'region_name': 'Oregon', 'city': 'Boardman', 'zip': '97818', 'latitude': 45.73722839355469, 'longitude': -119.81143188476562, 'location': {'geoname_id': None, 'capital': 'Washington D.C.', 'languages': [{'code': 'en', 'name': 'English', 'native': 'English'}], 'country_flag': 'http://assets.ipstack.com/flags/us.svg', 'country_flag_emoji': '🇺🇸', 'country_flag_emoji_unicode': 'U+1F1FA U+1F1F8', 'calling_code': '1', 'is_eu': False}, 'count': 2}
]
'''
