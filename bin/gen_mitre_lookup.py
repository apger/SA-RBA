#!/usr/bin/env python

#  Rev1 from Spico, Bryan Grant Nov 2019
#  Rev2 from Splunk, Jim Apger Mar 2020.  Expanded columns.


import sys
import splunk.Intersplunk as si
#import splunk.entity as entity
import json
import requests
import splunk.mining.dcutils as dcu


import six

def dispatch_types(value):
    if isinstance(value, six.integer_types):
        handle_integer(value)
    elif isinstance(value, six.class_types):
        handle_class(value)
    elif isinstance(value, six.string_types):
        handle_string(value)

logger = dcu.getLogger()
app = "SA-RBA"
results = []

if __name__ == '__main__':
    logger.info("SA-RBA gen_mitre_lookup.py Starting")
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    logger.info("SA-RBA gen_mitre_lookup.py requesting enterprise ATT&CK dict from url:{}".format(url))
    req = requests.Session()
    req.headers.update({'Accept': 'application/json'})
    jsonData = json.loads(req.get(url).content)
    
    for i in jsonData["objects"]:
        if i['type'] == 'attack-pattern':
            phase_name = []
            for x in i['kill_chain_phases']:
                phase_name.append(x['phase_name'])
            result = {}
            result["mitre_id"] = i['external_references'][0]['external_id']
            result["mitre_tactic"] = phase_name
            result["mitre_technique"] = i['name']
            result["mitre_description"] = i['description']
            result["mitre_url"] = i['external_references'][0]['url']
            if "x_mitre_detection" in i:
                result["mitre_detection"] = i['x_mitre_detection']
            results.append(result)

    logger.info("SA-RBA gen_mitre_lookup.py finished fetching {} objects".format(len(results)))

#print(results)
si.outputResults(results)
