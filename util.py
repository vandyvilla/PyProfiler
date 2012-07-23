#/usr/bin/python
import re

def matchRegex(regex, content):
        pattern = re.compile(r'^'+ regex + r'$')
        if pattern.match(content):
                return True
        else:
                return False

