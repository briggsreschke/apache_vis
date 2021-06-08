
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
    return next((index for (index, d) in enumerate(
        hosts) if d['ip'] == ip), None)


# Parse log records and take the IP and increment count for dups
parser = LogParser(apachelogs.COMBINED)
hosts = []
# ipstack access key
geo_lookup = GeoLookup("65eb4be1a0057db9222eb6e972e2051e")

for rec in log_records:
    entry = parser.parse(rec)
    ip = entry.remote_host

    if not search(hosts, ip):
        # new dict to add to hosts list
        location = geo_lookup.get_location(ip)
        dic = {}
        dic = location
        dic['count'] = 1
        hosts.append(dic)
    else:
        idx = index(hosts, ip)
        hosts[idx]['count'] += 1

with open("access_log.json", 'w') as outfile:
    outfile.write(json.dumps(hosts))
