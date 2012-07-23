#!/usr/bin/python

__version__ = "0.1"
__author__ = "xiaowei li <xli@mozilla.com>"

from profiler import Profiler 
from configuration import Configuration

import sys

def main():
	# check config file:
	if len(sys.argv) <= 1:
		print 'Please provide config file. '
		return
	config_file = sys.argv[1]
	# parse config file:
	config = Configuration(config_file)
	
	# init the profiler and get it working:
	profiler = Profiler(config)
	profiler.execute()	

if __name__ == '__main__':
	main()
