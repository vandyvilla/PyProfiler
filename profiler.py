#/usr/bin/python
import os
import log_parser
import util
from url_parser import urlParser
from resource_profile import Resource_profile

class Profiler:
	
	def __init__(self, config):
		self.config = config
		self.resource_map = {}
		self.resource_id = 0
		self.url_parser = urlParser(self.config.get_conf('ref_urls'))
		self.count = 0
		# debug purpose
		self.debug = False
		self.urls = {}

	def execute(self):
		dir = self.config.get_conf('log_dir')
		if not dir:
			print 'log_dir not initialized.'
			return
		for root, dirs, files in os.walk(dir):
                        for file in files:
                                print os.path.join(root,file)
                                f=open(os.path.join(root,file), 'r')
                                for line in f:
                                        res = log_parser.parse_line(line)
                                        if res and self.pass_filter(res):
						self.profile(res)
                                f.close()
		self.gen_output()


	def pass_filter(self, res):
		domain = res['domain']
                status = str(res['status'])
                # check domain first: 
                if domain != self.config.get_conf('app_host') and domain != self.config.get_conf('app_host')+':443':
			return False
		if status not in self.config.get_conf('status'):
			return False
		if res['request'] == '-':
			return False
		else:
			method = res['request'].split()[0]
			if method not in self.config.get_conf('methods'):
				return False
		return True


	def profile(self, res):
		self.count += 1
		method = res['request'].split()[0]
		url = res['request'].split()[1]

		resource = self.url_parser.parseUrl(url)
		resource.setMethod(method)

		# global profile.
		self.global_profile(resource)

		if self.debug:
			if resource.pattern not in self.urls:
				self.urls[resource.pattern] = []
			self.urls[resource.pattern].append(url)
	
		if resource.pattern not in self.resource_map:
			self.resource_id += 1
			self.resource_map[resource.pattern] = Resource_profile(self.resource_id, resource.pattern)
		self.resource_map[resource.pattern].process(resource, self)
		#self.resource_map[resource.pattern].set_regex_path(resource.regex_path)
	
	def global_profile(self, resource):
		pass	


	# find out the matching pattern:
	def match(self, string):
		for index in range(len(self.config.get_conf('patterns'))):
                	regex = self.config.get_conf('patterns')[index].regex
                	#print regex
                	if util.matchRegex(regex, string):
                        	return self.config.get_conf('patterns')[index].name
        	return 'NoMatch'

	# generate both xml files and modsecurity rules.
	def gen_output(self):
		print 'number of requests: ', self.count
		print 'number of url patterns: ', len(self.resource_map)

		# generate xml file
		#self.gen_xml(self.config.get_conf('output_xml'))
		self.gen_mod_sec_rules(self.config.get_conf('output_rules'))

		if self.debug:
			index = 1
			for key in self.urls:
				f = open('urls/'+str(index)+'_'+str(self.resource_map[key].count)+'_url', 'w')
				f.write('key: ' + key + '\n\n')
				for url in self.urls[key]:
					f.write(url + '\n')
				f.close()
				f = open('urls/'+str(index)+'_xml', 'w')
				self.resource_map[key].gen_xml(f)
				f.close()
				index += 1
					
		
	def gen_xml(self, file):
		f = open(file, 'w')
		f.write('<appmodel>\n')
		for key in self.resource_map.keys():
			#if self.resource_map[key].count >= self.config.get_conf('min_url_pattern_occur'):
			f.write('  <resource\n')
			f.write('    pattern=\"' + key + '\"\n')
			f.write('    count=\"' + str(self.resource_map[key].count) + '\"\n')
			self.resource_map[key].gen_xml(f)
			f.write('  </resource>\n')
		f.write('</appmodel>\n')
		f.close()


	def gen_mod_sec_rules(self, file):
		f = open(file, 'w')
		f.write('# resource threshold set at ' + str(self.config.get_conf('min_url_pattern_occur')) +'\n')
		f.write('# parameter threshold set at ' + str(self.config.get_conf('min_param_occur')) + '\n')
		f.write('# resource switch statements:\n\n')
		for key in self.resource_map:
			#print 'key: ', key, ' count: ', self.resource_map[key].count, ' ' , self.resource_map[key].regex_path 
			# only output url patterns having confidence.
			if self.resource_map[key].count >= int(self.config.get_conf('min_url_pattern_occur')):
				# entry point
				f.write('SecRule REQUEST_FILENAME \"^')
				f.write(self.resource_map[key].get_regex_path() + '$\"')
				f.write(' \"phase:2,t:none,t:lowercase,t:normalisePath,nolog,pass,skipAfter:' + self.config.get_conf('app_name') + '-' + str(self.resource_map[key].id) + ',auditlog\"\n\n')
				f.write('# resource: ' + self.resource_map[key].pattern + '\n')
				f.write('SecMarker ' + self.config.get_conf('app_name') + '-' + str(self.resource_map[key].id) + '\n')
				self.resource_map[key].gen_mod_sec_rules(f)
				f.write('# Jump to the end\n')
				f.write('SecAction nolog,skipAfter:' + self.config.get_conf('app_name') + '-END\n\n')
		f.write('# END of Rules\n')
		f.write('SecMarker ' + self.config.get_conf('app_name') + '-END\n\n')
		f.close()
