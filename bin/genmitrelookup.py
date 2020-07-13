import sys, time, json, splunk.mining.dcutils as dcu
sys.path.append("../lib")
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration
import splunklib.client as client
import six.moves.urllib.request, six.moves.urllib.parse, six.moves.urllib.error, six.moves.urllib.request, six.moves.urllib.error, six.moves.urllib.parse

#  Rev 1 author:  Jim Apger, Splunk (mayhem@splunk.com).  April 2020.  Initial release.
#  Rev 2 author:  Jim Apger, Splunk (mayhem@splunk.com).  April 2020.  Added MITRE ATT&CK Threat Groups
#  Rev 3 author:  Jim Apger, Splunk (mayhem@splunk.com).  April 2020.  Added MITRE ATT&CK Software

class group:
    def __init__(self,intrusion_id,external_id,name,aliases,description,x_mitre_version,url):
	self.intrusion_id = intrusion_id
	self.external_id = external_id
	self.name = name
	self.aliases = aliases
	self.description = description
	self.x_mitre_version =  x_mitre_version
	self.url =  url

class relationship:
    def __init__(self,relationship_id,attack_pattern,source_ref):
	self.relationship_id = relationship_id
	self.attack_pattern = attack_pattern
	self.source_ref= source_ref

class software:
    def __init__(self,software_id, external_id, name, software_label, platform, type, url, aliases) :
	self.software_id = software_id
	self.external_id = external_id
	self.name = name
	self.software_label = software_label
	self.platform = platform
	self.type = type
	self.url = url
	self.aliases = aliases

@Configuration()
class GenerateMitreCommand(GeneratingCommand):
    logger = dcu.getLogger()

    def generate(self):
	self.logger.info("SA-RBA genmitrelookup.py Starting")
	info = self.search_results_info #capture the getinfo context sent by splunkd
	self.logger.info("SA-RBA search_results_info: {}".format(info))
	url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
	self.logger.info("SA-RBA gen_mitre_lookup.py requesting enterprise ATT&CK dict from url:{}".format(url))
	req = six.moves.urllib.request.Request(url)
	search_results = six.moves.urllib.request.urlopen(req)
	jsonData = json.loads(search_results.read())
	self.logger.info("SA-RBA retrieved {} objects from the enterprise ATT&CK dict".format(len(jsonData['objects'])))

	service=client.connect(token=info.auth_token, owner='nobody')
	collection_name = "mitredict"
	collection = service.kvstore[collection_name]
	if collection_name in service.kvstore:
	    self.logger.info("SA-RBA KVStore Collection {} Found".format(collection_name))
	    self.logger.info("SA-RBA KVStore Deleting all data from collection {}".format(collection_name))
	    collection.data.delete()

	    json_obj=json.dumps(collection.data.query())
	    len_obj=len(json_obj.encode("utf-8"))

	    while len_obj > 4:
		time.sleep(2)
		self.logger.info("SA-RBA KVStore Deleting. Size of the collection:{}".format(obj_len))
		json_obj=json.dumps(collection.data.query())
		len_obj=len(json_obj.encode("utf-8"))
	else:
	    self.logger.info("SA-RBA KVStore Collection {} NOT Found".format(collection_name))

	# Grab all mitre relationship context from the mitre dict.  Techniques will map to these
	relationships=[]
	for r in jsonData["objects"]:
	    if r['type'] == 'relationship' and r['source_ref'].startswith("intrusion-set"):
		relationships.append(relationship(r['id'],r['target_ref'],r['source_ref']))
	    if r['type'] == 'relationship' and r['source_ref'].startswith("malware--"):
		relationships.append(relationship(r['id'],r['target_ref'],r['source_ref']))
	    if r['type'] == 'relationship' and r['source_ref'].startswith("tool--"):
		relationships.append(relationship(r['id'],r['target_ref'],r['source_ref']))
	self.logger.info("SA-RBA retrieved {} relationships from the enterprise ATT&CK dict".format(len(relationships)))    

	# Grab all mitre software context from the mitre dict.  Techniques will map to these via relationships
	softwares=[]
	for s in jsonData["objects"]:
	    x_mitre_platforms="none"
	    x_mitre_aliases="none"
	    if s['type'] == 'malware' or s['type'] == 'tool':
		if 'x_mitre_platforms' in s:
		    x_mitre_platforms=','.join(s['x_mitre_platforms']) #Convert the list to a string 
		if 'x_mitre_aliases' in s:
		    x_mitre_aliases=s['x_mitre_aliases']
		softwares.append(software(s['id'],s['external_references'][0]['external_id'],s['name'],s['labels'],x_mitre_platforms,s['type'],s['external_references'][0]['url'],x_mitre_aliases))
	self.logger.info("SA-RBA retrieved {} software object from the enterprise ATT&CK dict".format(len(softwares)))    

	# Grab all mitre threat group context from the mitre dict.  Techniques will map to these via relationships
	groups=[]
	for g in jsonData["objects"]:
	    aliases="none"
	    description="none"
	    x_mitre_version="none"
	    if g['type'] == 'intrusion-set':
		if 'aliases' in g:
		    aliases=','.join(g['aliases'])  #Convert the list to a string
		if 'description' in g:
		    description=g['description']
		if 'x_mitre_version' in g:
		    x_mitre_version=g['x_mitre_version']
		groups.append(group(g['id'],g['external_references'][0]['external_id'],g['name'],aliases,description,x_mitre_version,g['external_references'][0]['url']))
	self.logger.info("SA-RBA retrieved {} groups from the enterprise ATT&CK dict".format(len(groups)))    

	#Build a mapping of mitre tactic names to ids
	tactics={}
	for i in jsonData["objects"]:
	    if i['type'] == 'x-mitre-tactic':
		tactics.update({i['x_mitre_shortname']:i['external_references'][0]['external_id']})
	self.logger.info("SA-RBA Tactics discovered in the mitre dict: {}".format(tactics))

	# Grab all mitre technique context from the mitre dict
	for i in jsonData["objects"]:
	    self.logger.info("SA-RBA TEST 1: {}".format(i))
	    if i['type'] == 'attack-pattern':
		tactic_name = []
		tactic_name_id = []
                if 'kill_chain_phases' in i :
		    for x in i['kill_chain_phases']:
		        tactic_name.append(x['phase_name'])
		        tactic_name_id.append(tactics[x['phase_name']])
		result = {}
		result["mitre_technique_id"] = i['external_references'][0]['external_id']
		result["mitre_tactic"] = tactic_name
		result["mitre_tactic_id"] = tactic_name_id
		result["mitre_technique"] = i['name']
                if 'description' in i:
		    result["mitre_description"] = i['description']
                else:
                    result["mitre_description"] = ""
		result["mitre_url"] = i['external_references'][0]['url']
		if "x_mitre_detection" in i:
		    result["mitre_detection"] = i['x_mitre_detection']
		else:
		    result["mitre_detection"]="None"
	        self.logger.info("SA-RBA TEST 2 result: {}".format(result))

		# lets add threat group and software association based on the technique
		group_name=[]
		group_alias=[]
		group_url=[]
		group_external_id=[]
		software_name=[]
		software_type=[]
		software_platform=[]
		software_url=[]
	 	for r in relationships:
		    if r.attack_pattern == i['id'] and r.source_ref.startswith("intrusion-set"):
			for g in groups:
			    if r.source_ref == g.intrusion_id:
				group_name.append(g.name)
				group_alias.append(g.aliases)
				group_url.append(g.url)
				group_external_id.append(g.external_id)
		    if r.attack_pattern == i['id'] and (r.source_ref.startswith("malware--") or r.source_ref.startswith("tool--")):
			for s in softwares:
			    if r.source_ref == s.software_id:
				software_name.append(s.name)
				software_type.append(s.type)
				software_platform.append(s.platform)
				software_url.append(s.url)

		result['mitre_threat_group_name']=group_name
		result['mitre_threat_group_aliases']=group_alias
		result['mitre_threat_group_url']=group_url
		result['mitre_threat_group_id']=group_external_id
		result['mitre_software_name']=software_name
		result['mitre_software_type']=software_type
		result['mitre_software_platform']=software_platform
		result['mitre_software_url']=software_url

		#send them to stdout if you wanted to carry results into spl for something like an outputlookup
		#yield {'mitre_technique_id': result["mitre_technique_id"],\
		#	'mitre_tactic': result["mitre_tactic"],\
		#	'mitre_tactic_id': result["mitre_tactic_id"],\
		#	'mitre_technique': result["mitre_technique"],\
		#	'mitre_description': result["mitre_description"],\
		#	'mitre_url': result["mitre_url"],\
		#	'mitre_detection': result["mitre_detection"]}

				#write it to the KVStore
		collection.data.insert(json.dumps({"mitre_technique_id": result["mitre_technique_id"],\
		    "mitre_tactic": result["mitre_tactic"],\
		    "mitre_tactic_id": result["mitre_tactic_id"],\
		    "mitre_technique": result["mitre_technique"],\
		    "mitre_description": result["mitre_description"],\
		    "mitre_url": result["mitre_url"],\
		    "mitre_detection": result["mitre_detection"],\
		    "mitre_threat_group_name": result["mitre_threat_group_name"],\
		    "mitre_threat_group_aliases": result["mitre_threat_group_aliases"],\
		    "mitre_threat_group_url": result["mitre_threat_group_url"],\
		    "mitre_software_name": result["mitre_software_name"],\
		    "mitre_software_type": result["mitre_software_type"],\
		    "mitre_software_platform": result["mitre_software_platform"],\
		    "mitre_software_url": result["mitre_software_url"]}))

	self.logger.info("SA-RBA genmitrelookup.py finished")
	yield {'_time': time.time(),'_raw':'SA-RBA genmitrelookup.py finished'}


if __name__ == "__main__":
    dispatch(GenerateMitreCommand, sys.argv, sys.stdin, sys.stdout, __name__)
