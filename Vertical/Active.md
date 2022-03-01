 https://sidxparab.gitbook.io/subdomain-enumeration-guide/
# DNS Bruteforcing
## PureDNS
Generate list of open public resolvers
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt

```bash
puredns bruteforce wordlist.txt example.com -r resolvers.txt -w output.txt --wildcard-batch 1000000
```

#### Wordlist to use
**1) Assetnote** [**best-dns-wordlist.txt**](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt) (**9 Million**)

**2) Jhaddix** [**all.txt**](https://gist.github.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a) (**2 Million**)

**3) Smaller** [**wordlist**](https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw) (**102k** )

# Permutation
## DNSCewl
https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw
```bash
DNScewl --tL subdomains.txt -p permutations_list.txt --level=0 --subs --no-color | tail -n +14 > permutations.txt
```
Resolution:
Now that we have made a huge list of all the possible subdomains that could exist, now it's time to DNS resolve them and check for valid ones.
```bash
puredns resolve permutations.txt -r resolvers.txt
```
## Gotator
-   First, we need to make a combined list of all the subdomains(valid/invalid) we collected from all the above steps whose permutations we will create.
    
-   To generate combinations you need to provide a small wordlist that contains common domain names like admin, demo, backup, api, ftp, email, etc.
    
-   [This](https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw) is a good wordlist of 1K permutation words that we will need.
    
-   The below command generates a huge list of non-resolved subdomains.
```bash
gotator -sub subdomains.txt -perm permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md > gotator1.txt
```
Next, run `puredns` to resolves the DNS as the command above.

# Scraping (JS/Source code)
## Gospider
1/ Web probing subdomains
```bash
cat subdomains.txt | httpx -random-agent -retries 2 -no-color -o probed_tmp_scrap.txt
```
```bash
gospider -S probed_tmp_scrap.txt --js -t 50 -d 3 --sitemap --robots -w -r > gospider.txt
```
2/ Cleaning the output
```bash
sed -i '/^.\{2048\}./d' gospider.txt
```
```bash
cat gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".example.com$" | sort -u scrap_subs.txt
```

3/ Resolving subdomains
```bash
puredns resolve scrap_subs.txt -w scrap_subs_resolved.txt -r resolvers.txt
```

# Google analytics
## AnalyticRelationships
```
./analyticsrelationships --url https://www.bugcrowd.com
```

# TLS, CSP, CNAME Probing
1/. TLS Probing
```
cero in.search.yahoo.com | sed 's/^*.//' | grep -e "\." | anew 
```
2/. CSP Probing
```
cat subdomains.txt | httpx -csp-probe -status-code -retries 2 -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q csp_subdomains.txt
```
3/. CNAME Probing
```
dnsx -retry 3 -cname -l subdomains.txt
```