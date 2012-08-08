#PyProfiler

This project aims to automatically generate modsecurity (firewall) rules from Apache access logs. The idea is that instead of using attack signatures (i.e., based on negative security model, DEFAULT ALLOW), we use the application profile (i.e., based on positive security model, DEFAULT DENY) to specify "what the normal web requests should look like". The modSecurity ruleset can also be transformed into zeus spec (.xml) that can be imported by Stingray (a commercial WAF). 

##Usage:

* edit profiler.conf: profiler.conf contains all the configurations for the profiler. 
* run: python main.py profiler.conf: provide the configuration file; the output is the modsecurity ruleset.
* run: python mod2zeus.py: the output is the zeus spec file (.xml).


