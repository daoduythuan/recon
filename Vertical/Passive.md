Passive subdomain enumeration is a technique to query passive DNS datasets provided by sources ([Security trails](https://securitytrails.com), [Censys](https://censys.io), [Shodan](https://www.shodan.io), [Binaryedge](https://www.binaryedge.io), [Virus total](https://www.virustotal.com/gui/)) to obtain the subdomains of a particular target.

# <u> 4 steps to do </u>
--------------------

## I. Passive DNS gathering tools
-Amass
```
amass enum -passive -d example.com -config /root/.config/amass/config.ini -o output.txt
```
-Subfinder
```
subfinder -d example.com -all -config /root/.config/subfinder/config.yaml -o output.txt
```
-Assetfinder
```
assetfinder --subs-only example.com > output.txt
```

-Findomain
```
findomain -t example.com
```
-------------------

## II. Internet Archive
-gau-plus
```
gauplus -t 5 -random-agent -subs example.com | unfurl -u domains | anew output.txt
```
-waybackurls
```
waybackurls example.com | unfurl -u domains | sort -u output.txt
```
-------------------

## III. Github scraping
-github-subdomains
```
github-subdomains -d example.com -t tokens.txt -o output.txt
```
-------------------

## IV. The Rapid7 Project Sonar
-Crobat
```
crobat -s example.com > output.txt
```
-------------------

## Certificate Logs
```
https://crt.sh/?q=%25.dell.com
```
```
python3 go/bin/ctfr/ctfr.py -d target.com -o output.txt
```
```
curl "https://tls.bufferover.run/dns?q=.dell.com" | jq -r .Results[] | cut -d ',' -f3 | grep -F ".dell.com" | anew -q output.txt
```
```
curl "https://dns.bufferover.run/dns?q=.dell.com" | jq -r '.FDNS_A'[],'.RDNS'[] | cut -d ',' -f2 | grep -F ".dell.com" | anew -q output.txt
```


## Recursive Enumeration
```bash
for sub in $( ( cat subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
    subfinder -d example.com-all -silent | anew -q passive_recursive.txt
    assetfinder --subs-only example.com | anew -q passive_recursive.txt
    amass enum -passive -d example.com | anew -q passive_recursive.txt
    findomain --quiet -t example | anew -q passive_recursive.txt
done
```