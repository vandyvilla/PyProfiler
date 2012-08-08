#PyProfiler

This project aims to automatically generate modsecurity rules from Apache access logs

 for modSecurity and Zeus application firewall. 




##Usage:

* edit profiler.conf: profiler.conf contains all the configurations for the profiler. 
* run: python main.py profiler.conf. the output is the modsecurity ruleset. 
* run: python mod2zeus.py: the input 
