#/usr/bin/python

class Resource:

        def __init__(self, pattern):
                self.pattern = pattern
                self.params = {}

        def setParams(self, params):
                self.params.update(params)

	def setRegexPath(self, path):
		self.regex_path = path

	def setMethod(self, method):
		self.method = method
