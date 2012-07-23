#!/usr/bin/python

class Configuration:
	'Class for maintaining all configurations'
	
	def __init__(self, config_file):
		self.configurations = {}
		self.configurations['patterns'] = []
		self.configurations['methods'] = []
		self.configurations['status'] = []
		self.pattern_map = {}
		self.parse_config(config_file)
		self.print_config()

	
	def parse_config(self, config_file):
		for line in open(config_file, 'rb').readlines():
			if (len(line.strip()) != 0 and not line.startswith('#')):
				#print line
				if (line.startswith('logDir')):
					self.configurations['log_dir'] = line.split('=')[1].strip()
				elif (line.startswith('appName')):
					self.configurations['app_name'] = line.split('=')[1].strip()
				elif (line.startswith('appHost')):
					self.configurations['app_host'] = line.split('=')[1].strip()
				elif (line.startswith('outputXml')):
					self.configurations['output_xml'] = line.split('=')[1].strip()
				elif (line.startswith('outputRules')):
					self.configurations['output_rules'] = line.split('=')[1].strip()	
				elif (line.startswith('refUrls')):
					self.configurations['ref_urls'] = line.split('=')[1].strip()
				elif (line.startswith('methods')):
					methods = line.split('=')[1].strip().split('|')
					self.configurations['methods'].extend(methods)
				elif (line.startswith('status')):
					status = line.split('=')[1].strip().split('|')
					self.configurations['status'].extend(status)
				elif (line.startswith('minUrlPatternOccurence')):
					self.configurations['min_url_pattern_occur'] = line.split('=')[1].strip()
				elif (line.startswith('minParamOccurence')):
					self.configurations['min_param_occur'] = line.split('=')[1].strip()
				elif (line.startswith('pattern.')):
					p = Pattern(line.split('=')[0].strip(), line.split('=')[1].strip())
					self.configurations['patterns'].append(p)  #the order of patterns matters!		
					self.pattern_map[p.name] = p.regex				

	def print_config(self):
		for key in self.configurations:
			if key == 'patterns':
				continue
			print key, ' : ', self.configurations[key] 
		for p in self.configurations['patterns']:
			print p.toString()
	
	def get_conf(self, key):
		return self.configurations[key]

class Pattern:
	'Class for regex pattern'
	
	def __init__(self, name, regex):
		self.name = name
		self.regex = regex
		self.count = 0
 
	def toString(self):
		return self.name+' : '+self.regex
