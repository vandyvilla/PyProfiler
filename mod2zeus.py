#/usr/bin/python
import copy
import xml.etree.ElementTree as xml

class mod2zeus_adapter:

	def __init__(self):
		self.mod_rules = []

	def load_zeus_xml(self, in_file):
		self.tree = xml.parse(in_file)

	def output_zeus_xml(self, out_file):
		self.tree.write(out_file)
        	with open(out_file,'r+') as f:
                	content = f.read()
                	f.seek(0,0)
                	f.write('<?xml version="1.0" encoding="UTF-8" ?>\n<!DOCTYPE params PUBLIC "-//AOD//DTD HG 1.0//EN" "./hg_import_export.dtd">\n')
                	f.write(content)
                	f.close()

	# helper functions:
	def findMembersWithName(self, element, path, name):
	        member_list = []
        	members = element.findall(path+'struct/member')
        	for member in members:
                	if member.find('name').text == name:
                        	member_list.append(member)
        	return member_list

	def getNameValue(self, element):
        	return element.find('value/string').text

	def setStructNameValue(self, struct, value):
        	names = self.findMembersWithName(struct, '', 'name')
        	for name in names:
                	name.find('value/string').text = value

	def findStructWithNameValue(self, element, path, value):
        	structs = element.findall(path+'value/array/data/value')
        	for struct in structs:
                	names = self.findMembersWithName(struct, '', 'name')
                	for name in names:
                        	if self.getNameValue(name) == value:
                                	return struct

	# add a prefix to zeus spec tree
	def add_prefix(self, prefix):
		data = self.findMembersWithName(self.tree, 'param/value/', 'data')[0]
        	rules = self.findMembersWithName(data, 'value/', 'rules')[0]
		base = self.findStructWithNameValue(rules, '', '/.*')
        	# add new rule/prefix/deep copy
		new_prefix = copy.deepcopy(base)
		print 'add prefix: ', prefix.pattern
        	self.setStructNameValue(new_prefix, prefix.pattern)

        	handlers = self.findMembersWithName(new_prefix, '', 'handler')[0]
        	mod_emu_handler = self.findStructWithNameValue(handlers, '', 'ModSecurityEmulationHandler')

        	mod_emu_config = self.findMembersWithName(mod_emu_handler, '', 'ConfigItems')[0]
        	mod_emu_rules = self.findStructWithNameValue(mod_emu_config, '', 'rules')
		
		# construct a list of rule nodes.
		new_rules = []
		for rule in prefix.rules:
			v = xml.Element('value')
			r = xml.SubElement(v, 'string')
			r.text = rule
			new_rules.append(v)

		# check if any rules pre-exist (not actually):
        	if len(self.findMembersWithName(mod_emu_rules, '', 'value')) == 0:
                	m = xml.Element('member')
                	n = xml.SubElement(m, 'name')
                	n.text = 'value'
                	v = xml.SubElement(m, 'value')
                	a = xml.SubElement(v, 'array')
                	d = xml.SubElement(a, 'data')
		
        	        d.extend(new_rules)
                	mod_emu_rules.find('struct').append(m)

        	else:
                	rule_list = self.findMembersWithName(mod_emu_rules, '', 'value')[0].find('value/array/data')
                	rule_list.extend(new_rules)

		# be careful of prefix order!!	
        	rules.find('value/array/data').insert(0, new_prefix)


	def add_mod_rules(self, rule_file):
	# the order of prefix matters! 
		f = open(rule_file, 'r')
		index = 0
		for line in f:
			line = line.strip()
			# jump comments
			if line == '' or line.startswith('#'):
				continue
			# new prefix
			if line.startswith('SecRule REQUEST_FILENAME'):
				prefix = line.split()[2]
				self.mod_rules.append(Prefix(prefix))
				index += 1
			elif line.startswith('SecRule'):
				# new rule
				if index > 0:
					# replace 'pass' in rule with 'deny'
					line = line.replace('pass', 'deny')
					self.mod_rules[index-1].add_rule(line)
		for index in range(len(self.mod_rules)):
			self.add_prefix(self.mod_rules[index])


class Prefix:
	
	def __init__(self, pattern):
		self.pattern = pattern
		self.rules = []
	
	def add_rule(self, rule):
		self.rules.append(rule)


if __name__ == '__main__':
	adapter = mod2zeus_adapter()
	adapter.load_zeus_xml('base_mkt_zeus_spec.xml')
	adapter.add_mod_rules('mkt_rules.conf')
	adapter.output_zeus_xml('new_mkt_zeus_spec.xml')
