#!/usr/bin/python

import re
import os

# parse a log line
def parse_line(line):
	parts = [
    		r'(?P<host>\S+)',                   # host %h
		r'(?P<domain>\S+)',
    		#r'\S+',                            # indent %l (unused)
    		r'(?P<user>\S+)',                   # user %u
    		r'\[(?P<time>.+)\]',                # time %t
    		r'"(?P<request>.+)"',               # request "%r"
    		r'(?P<status>[0-9]+)',              # status %>s
    		r'(?P<size>\S+)',                   # size %b (careful, can be '-')
    		r'"(?P<referer>.*)"',               # referer "%{Referer}i"
    		r'"(?P<agent>.*)"',                 # user agent "%{User-agent}i"
		r'"(?P<cookie>.*)"',		    # cookie "%{Cookie}i"
	]
	pattern = re.compile(r'\s+'.join(parts)+r'\s*\Z')
	m = pattern.match(line)
	if not m:
		#print 'NoneType: m, ', line
		return
	res = m.groupdict()		
	res["status"] = int(res["status"])
	if res["size"] == "-":
    		res["size"] = 0
	else:
    		res["size"] = int(res["size"])
	return res

# parse the logs in a directory
def parse_dir(dir):
	for root, dirs, files in os.walk(dir):
		for file in files:
			print os.path.join(root,file)
			f=open(os.path.join(root,file), 'r')
			for line in f: 
				print parse_line(line)
			f.close()



months = {
    'Jan':'01',
    'Feb':'02',
    'Mar':'03',
    'Apr':'04',
    'May':'05',
    'Jun':'06',
    'Jul':'07',
    'Aug':'08',
    'Sep':'09',
    'Oct':'10',
    'Nov':'11',
    'Dec':'12'
    }

def parse_date(date):
    """
    Takes a date in the format: [05/Dec/2006:10:51:44 +0000]
    (including square brackets) and returns a two element
    tuple containing first a timestamp of the form
    YYYYMMDDHH24IISS e.g. 20061205105144 and second the
    timezone offset as is e.g.;

    parse_date('[05/Dec/2006:10:51:44 +0000]')
    >> ('20061205105144', '+0000')

    It does not attempt to adjust the timestamp according
    to the timezone - this is your problem.
    """
    date = date[1:-1]
    elems = [
        date[7:11],
        months[date[3:6]],
        date[0:2],
        date[12:14],
        date[15:17],
        date[18:20],
        ]
    return (''.join(elems),date[21:])
			
