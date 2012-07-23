#/usr/bin/python
from url_tree import urlTree
from resource import Resource
import util

class urlParser:

	def __init__(self, ref_urls):
		if not ref_urls:
			print 'ref_urls not initialized.'
                        return
		self.url_tree = self.load_ref_urls(ref_urls)

	def load_ref_urls(self, urls):
                tree = urlTree()
                f = open(urls, 'r')
                count = 0
                for line in f:
                        count += 1
                        url = line.split()[0].strip()
                        tree.add_path(url)
                f.close()
                print 'number of ref urls loaded: ', count
                #tree.output('urltree')
                return tree	

	def parseUrl(self, url):
		debug = False
		if debug: print url
		if url.find('?') == -1:
			path = url
			para = ''
		else: 
			path = url[:url.find('?')]
			para = url[url.find('?'):][1:]
		params = {}
		pattern = ''
		regex_path = ''
		cur_node = self.url_tree.root
		# start processing url:
		comps = path.split('/')
		for index in range(len(comps)):
			item = comps[index]
			if item == '':
				continue
			# check lang code:
			if index == 1:
				if util.matchRegex('[a-z][a-z](-[A-Z][A-Z])?', item):
                                        pattern += '/<pattern.lang>'
					regex_path += '/([a-z][a-z](-[A-Z][A-Z])?)'
                                        continue
			# walk the url tree:
			if item in cur_node.children:
                                cur_node = cur_node.children[item]
                                pattern += '/' + item
				regex_path += '/' + item
                        else:
                                token = ''
                                match = False
                                for child in cur_node.children.keys():
                                        # check for placeholder:
                                        if util.matchRegex('<[\S]+>', child):
                                                #print 'match:', child
                                                if token == '':
                                                        token = '/' + child
							param_token = '/([a-zA-Z0-9._-]+)'
                                                match = True
                                                # only one regex match. 
                                                #else:
                                                #       reg += '|' + child

                                                # store param value.(only one)
                                                params[child] = item
                                                cur_node = cur_node.children[child]
                                                break
                                if match:
                                        pattern += token
					regex_path += param_token
                                else:
                                        pattern += '/' + item
					regex_path += '/' + item
		if debug: print 'url pattern: ', pattern
		res = Resource(pattern)
		#res.setRegexPath(regex_path)
		
		if para != '':
			parts = para.split('&')
			for part in parts:
				if part.find('=') == -1:
					continue
				name = part.split('=')[0]
                                value = part.split('=')[1]
				params[name] = value
		res.setParams(params)
		return res
