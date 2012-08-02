#/usr/bin/python
from param_profile import Param_profile 

class Resource_profile:

	def __init__(self, id, pattern):
		self.id = id
		# the resource key
		self.pattern = pattern
		# the allowed HTTP method
		self.methods = {}
		# possible parameters
		self.params = {}
		self.count = 0
		self.param_thre = 0
	

	def process(self, resource, profiler):
		if self.param_thre == 0:
			self.param_thre = int(profiler.config.get_conf('min_param_occur'))
		self.count += 1
		# record the http method
		if resource.method not in self.methods:
			self.methods[resource.method] = 0
		self.methods[resource.method] += 1

		# proces parameters.
	 	for param in resource.params.keys():
			if param not in self.params:
				self.params[param] = Param_profile(param)
			self.params[param].process(resource.params[param], profiler)



	def gen_xml(self, f_handler):
		# AppSensor RE3, RE4
		for method in self.methods:
			if self.methods[method] == self.count:
				f_handler.write('    method=\"' + method + '\"\n')

		# AppSensor RE6: always expecting the parameter
		f_handler.write('    param=\"')
		for param in self.params:
			if self.params[param].count == self.count:
				f_handler.write(param+' ')
		f_handler.write('\"\n')
		f_handler.write('  >\n')
		
		# AppSensor RE5: all observed parameters.
		for param in self.params:
			self.params[param].gen_xml(f_handler)


	def get_regex_path(self):
		self.regex_path = self.pattern
		self.regex_path = self.regex_path.replace('<pattern.lang>', '[a-z][a-z](-[A-Z][A-Z])?')
		for param in self.params:
			if param.find('<') == -1 or param.find('>') == -1:
				continue
			if self.regex_path.find(param) != -1:
				self.regex_path = self.regex_path.replace(param, self.params[param].get_pattern_list())
		print self.regex_path
		return self.regex_path
	

	def set_regex_path(self, path):
		self.regex_path = path


	def get_param_list(self):
		list = ''
		index = 0
		for param in self.params:
			if (param.find('<') != -1 and param.find('>') != -1):
				continue
			if index != 0:
				list += '|'
			list += param
			index += 1
		return list


	def gen_mod_sec_rules(self, f_handler):
		# AppSensor RE3,4: check HTTP request method:
		for method in self.methods:
			# skip evaluating POST requests/parameters
			if method == 'POST':
				return
                        #if self.methods[method] == self.count:
                        #        f_handler.write('SecRule REQUEST_METHOD \"!' + method + '\" \"phase:2,t:none,log,pass,setvar:tx.anomaly_score=+1,msg:\'AppSensor RE3/4 - unexpected HTTP method\'\"\n')

		# AppSensor RE5: check all observed parameters:
		param_list = self.get_param_list()
		if param_list != '':
			f_handler.write('SecRule ARGS_NAMES \"!^(')
			f_handler.write(param_list)
			f_handler.write(')$\" \"phase:2,log,pass,setvar:tx.anomaly_score=+1,msg:\'AppSensor RE5 - unexpected HTTP parameter\'\"\n')

		for param in self.params:
			if (param.find('<') != -1 and param.find('>') != -1):
                                continue
			# check parameter occurence
			if self.params[param].count >= self.param_thre:
				self.params[param].gen_mod_sec_rules(f_handler)
				# check cardinality:
				f_handler.write('SecRule &ARGS:' + param + ' \"@gt 1\" \"phase:2,log,pass,setvar:tx.anomaly_score=+1,msg=\'parameter appears more than once\'\"\n')
				if self.params[param].count == self.count:
					f_handler.write('SecRule &ARGS:' + param + ' \"@lt 1\" \"phase:2,log,pass,setvar:tx.anomaly_score=+1,msg=\'required parameter does not appear\'\"\n')
			
