#/usr/bin/python
from configuration import Pattern
import math

class Param_profile:

	def __init__(self, name):
		self.name = name
		self.values = []
		self.count = 0
		# length feature: mean + std.
		self.lengths = []		
		# character pattern: should be robust to errors/attacks in logs.
		self.patterns = {}
	

	def process(self, value, profiler):
		self.values.append(value)
		self.count += 1
		self.lengths.append(len(value))

		# match patterns:
		pattern = profiler.match(value)
		if pattern == 'NoMatch':
			return
		if pattern not in self.patterns:
			regex = profiler.config.pattern_map[pattern]
			self.patterns[pattern] = Pattern(pattern, regex)
		self.patterns[pattern].count += 1

	
	def gen_xml(self, f_handler):
		f_handler.write('    <param\n')
		f_handler.write('      name=\"' + self.name + '\"\n')	
		f_handler.write('      count=\"' + str(self.count) + '\"\n')	
		self.compute_len()
		f_handler.write('      len_mean=\"' + str(int(self.len_mean)) + '\"\n')
		f_handler.write('      len_std=\"' + str(int(self.len_std)) + '\"\n')
		f_handler.write('    >\n')
		# content patterns:
		for pattern in self.patterns:
			f_handler.write('      <pattern\n')
			f_handler.write('        name=\"' + self.patterns[pattern].name + '\"\n')
			f_handler.write('        count=\"' + str(self.patterns[pattern].count) + '\"\n')
			f_handler.write('      </pattern>\n')

		f_handler.write('    </param>\n')

	
	def average(self, s):
		return sum(s)*1.0/len(s)

	# compute the mean and std of parameter length.
	def compute_len(self):
		self.len_mean = self.average(self.lengths)
		variance = map(lambda x:(x - self.average(self.lengths))**2, self.lengths)
		self.len_std = math.sqrt(self.average(variance))
		#print self.len_mean, ' ', self.len_std
	

	def get_pattern_list(self):
		list = ''
		for pattern in self.patterns:
			# appear more than once:
			if self.patterns[pattern].count > 1:
				if list == '':
					list += '(' + self.patterns[pattern].regex + ')'
				else:
					list += '|(' + self.patterns[pattern].regex + ')'
		return list

	# statistical test.
	def ks_test(self):
		return False
			

	def get_value_list(self):
		list = ''
		for value in self.values:
			if list == '':
				list += value
			else:
				list += '|' + value
		return list
	

	def gen_mod_sec_rules(self, f_handler):
		self.compute_len()
		# AppSensor RE7: check parameter length
		if self.len_std != 0:
			f_handler.write('SecRule ARGS:' + self.name + ' \"@gt ' + str(int(self.len_mean+self.len_std)) + '\" \"phase:2,t:none,t:length,log,pass,setvar:tx.anomaly_score=+1,msg:\'AppSensor:RE7: unexpected longer parameter length\'\"\n')	
			if int(self.len_mean - self.len_std) > 0:
				f_handler.write('SecRule ARGS:' + self.name + ' \"@lt ' + str(int(self.len_mean-self.len_std)) + '\" \"phase:2,t:none,t:length,log,pass,setvar:tx.anomaly_score=+1,msg:\'AppSensor:RE7: unexpected shorter parameter length\'\"\n')	
		else: 
			f_handler.write('SecRule ARGS:' + self.name + ' \"@eq ' + str(int(self.len_mean)) + '\" \"phase:2,t:none,t:length,log,pass,setvar:tx.anomaly_score=+1,msg:\'AppSensor:RE7: unexpected parameter length\'\"\n')	
		
		# AppSensor RE8: check content pattern
		p_list = self.get_pattern_list()
		if p_list != '':
			f_handler.write('SecRule ARGS:' + self.name + ' \"!@rx ' + p_list + '\" \"phase:2,t:none,log,pass,setvar:tx.anomaly_score=+1,msg:\'AppSensor:RE8: unexpected parameter content pattern\'\"\n')

		# check if parameter value expected.
		if self.ks_test():
			v_list = self.get_value_list()
			f_handler.write('SecRule ARGS:' + self.name + ' \"!@within ' + v_list + '\" \"phase:2,t:none,log,pass,setvar:tx.anomaly_score=+1,msg:\'unexpected parameter value\'\"\n')
			

