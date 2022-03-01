# Discovering the IP space
ASN: https://bgp.he.net/
IP Range: 
```bash
whois -h whois.radb.net -- '-i origin ASN Number' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq
```

# Finding related domains/acquisitions
duythuan2294@gmail.com / b0rnt0h4ck!@#A
https://tools.whoisxmlapi.com/reverse-whois-search

daoduythuan.IT@gmail.com / b0rnt0h4ck
API KEY = fef9ea003d6df0681l020b0ff41f06c4f
https://www.whoxy.com/

# Pointer Record - Reverse DNS
What is reverse DNS? When a user attempts to reach a domain name in their browser, a DNS lookup occurs, matching the domain name(example.com) to the IP address(such as 192.168.1.1). A reverse DNS lookup is the opposite of this process: it is a query that starts with the IP address and looks up the domain name.
```bash
echo 17.0.0.0/8 | mapcidr -silent | dnsx -ptr -resp-only -o output.txt
```
This means that, since we already know the IP space of an organization we can, we can reverse query the IP addresses and find the valid domains. Sounds cool?

```bash
whois -h whois.radb.net -- '-i origin AS714' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | mapcidr -silent | dnsx -ptr -resp-only
 ```
 
 # Favicon Hashing
```bash
python3 murmurhash.py
``` 
 Shodan: http.favicon.hash:\<hash\>
 
 #  Workflow
 ASN 
 |-> IP Range of  Space -> Open Port + Service Running (nabu, dnmasscan,masscan,brutesparying)
 |-> Reverse DNS: Sub domain takeover (SubOver, nuclei)