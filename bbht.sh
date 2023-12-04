#!/bin/bash
export WHOXY_API_KEY="fef9ea003d6df0681l020b0ff41f06c4f"
export PATH=$PATH:/Users/thuandao/go/bin
export CONFIG=/Users/thuandao/bbht/config
hor_1_whois(){
    echo "https://bgp.he.net/"
    whois -h whois.radb.net -- "-i origin $1" | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq
}

hor_2_RevDNS(){
    echo $1 | mapcidr -silent | dnsx -ptr -resp-only -o horizontal_2_RevDNS.txt
}

hor_3_murhash(){
    python3 /Users/thuandao/go/bin/MurMurHash/MurMurHash.py
}
###############
ver_pass_1_amass(){
    amass enum -list -config $CONFIG/amass.ini
    amass enum -passive -d $1 -config $CONFIG/amass.ini -o ver_pass_1_amass.txt
}
ver_pass_2_subfinder(){
    subfinder -d $1 -all -config /Users/thuandao/.config/subfinder/provider-config.yaml -o ver_pass_2_subfinder.txt
}
ver_pass_3_asset(){
    assetfinder --subs-only $1 > ver_pass_3_asset.txt
}
ver_pass_4_findomain(){
    findomain -t $1 -u ver_pass_4_findomain.txt
}
ver_pass_5_gau(){
    gauplus -t 5 -random-agent -subs $1 | unfurl -u domains | anew ver_pass_5_gau.txt
}
ver_pass_6_wayback(){
    waybackurls $1 | unfurl -u domains | sort -u -o ver_pass_6_wayback.txt
}

final_ver_pass(){
    cat ver_pass_* | tee $1-subdomains.txt | sort -u $1-subdomains.txt
}

ver_pass_recur(){
for sub in $( ( cat subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
    subfinder -d $sub -all -silent | anew -q passive_recursive.txt
    assetfinder --subs-only $sub | anew -q passive_recursive.txt
    amass enum -list -config $CONFIG/amass.ini | amass enum -passive -d $sub | anew -q passive_recursive.txt
    findomain --quiet -t $sub | anew -q passive_recursive.txt
done
}

fetch_url(){
    echo "Running katana"
    cat $1-subdomains.txt | katana -list $1-subdomains.txt -silent -jc -kf all -d 3 -fs rdn -c 30 | grep -Eo "https?://([a-z0-9]+[.])*$1.*"
    echo "Running GAU"
    cat $1-subdomains.txt | /Users/thuandao/go/bin/gau --threads 60 #| grep -Eo "https?://([a-z0-9]+[.])*$1.*"
    echo "Running hakrawler"
    cat $1-subdomains.txt | httpx -silent | hakrawler -subs -u | grep -Eo "https?://([a-z0-9]+[.])*$1.*"
    echo "Running waybackurls"
    cat $1-subdomains.txt | waybackurls | grep -Eo "https?://([a-z0-9]+[.])*$1.*"
}

scan_port(){
    naabu -json -exclude-cdn -list $1-subdomains.txt -top-ports 1000 -c 30 -rate 1500 -timeout 5000 -silent
}

craw_http(){
    httpx -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent -t 30 -json -l $1-subdomains.txt -silent -fr | grep -v "context deadline exceeded" | grep -v "no address found for host"
}