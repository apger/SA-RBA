import sys, time, json, splunk.mining.dcutils as dcu
sys.path.append("../lib")
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration
import splunklib.client as client
import six.moves.urllib.request, six.moves.urllib.parse, six.moves.urllib.error, six.moves.urllib.request, six.moves.urllib.error, six.moves.urllib.parse

#  Rev 1 author:  Jim Apger, Splunk (mayhem@splunk.com).  April 2020.  Initial release.
#  Rev 2 author:  Jim Apger, Splunk (mayhem@splunk.com).  April 2020.  Added MITRE ATT&CK Threat Groups

class group:
    def __init__(self,intrusion_id,external_id,name,aliases,description,x_mitre_version):
	self.intrusion_id = intrusion_id
	self.external_id = external_id
	self.name = name
	self.aliases = aliases
	self.description = description
	self.x_mitre_version =  x_mitre_version

class relationship:
    def __init__(self,relationship_id,attack_pattern,intrustion_id):
	self.relationship_id = relationship_id
	self.attack_pattern = attack_pattern
	self.intrusion_id = intrustion_id

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
	    #self.logger.info("SA-RBA KVStore data: {}".format(json.dumps(collection.data.query(), indent=1)))
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

	relationships=[]
	for r in jsonData["objects"]:
	    if r['type'] == 'relationship' and r['source_ref'].startswith("intrusion-set"):
		relationships.append(relationship(r['id'],r['target_ref'],r['source_ref']))
	self.logger.info("SA-RBA retrieved {} relationships from the enterprise ATT&CK dict".format(len(relationships)))    
 	#print(vars(relationships[0]))

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
		groups.append(group(g['id'],g['external_references'][0]['external_id'],g['name'],aliases,description,x_mitre_version))
	self.logger.info("SA-RBA retrieved {} groups from the enterprise ATT&CK dict".format(len(groups)))    
	#print(vars(groups[0]))







	#Build a mapping of mitre tactic names to ids
	tactics={}
	for i in jsonData["objects"]:
	    if i['type'] == 'x-mitre-tactic':
		tactics.update({i['x_mitre_shortname']:i['external_references'][0]['external_id']})
	self.logger.info("SA-RBA Tactics discovered in the mitre dict: {}".format(tactics))

	# Grab all mitre technique context from the mitre dict
	for i in jsonData["objects"]:
	    if i['type'] == 'attack-pattern':
		tactic_name = []
		tactic_name_id = []
		for x in i['kill_chain_phases']:
		    tactic_name.append(x['phase_name'])
		    tactic_name_id.append(tactics[x['phase_name']])
		result = {}
		result["mitre_technique_id"] = i['external_references'][0]['external_id']
		result["mitre_tactic"] = tactic_name
		result["mitre_tactic_id"] = tactic_name_id
		result["mitre_technique"] = i['name']
		result["mitre_description"] = i['description']
		result["mitre_url"] = i['external_references'][0]['url']
		if "x_mitre_detection" in i:
		    result["mitre_detection"] = i['x_mitre_detection']
		else:
		    result["mitre_detection"]="None"


		n=[]
		a=[]
		for r in relationships:
		    if r.attack_pattern == i['id']:
			for g in groups:
			    if r.intrusion_id == g.intrusion_id:
				n.append(g.name)
				a.append(g.aliases)
		result['mitre_threat_group_name']=n
		result['mitre_threat_group_aliases']=a

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
		    "mitre_threat_group_aliases": result["mitre_threat_group_aliases"]}))

	self.logger.info("SA-RBA genmitrelookup.py finished")
	yield {'_time': time.time(),'_raw':'SA-RBA genmitrelookup.py finished'}


if __name__ == "__main__":
    dispatch(GenerateMitreCommand, sys.argv, sys.stdin, sys.stdout, __name__)
