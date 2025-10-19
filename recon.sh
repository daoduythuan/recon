#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
export WHOXY_API_KEY="fef9ea003d6df0681l020b0ff41f06c4f"
export CONFIG=/home/ubuntu/.config/
export wordlist_path=/Users/daoduythuan/bbht/
export PATH=$PATH:/home/ubuntu/go/bin

# ============================================
# VERTICAL PASSIVE RECONNAISSANCE
# ============================================

# Passive subdomain enumeration using Amass
ver_pass_1_amass(){
    echo "[*] Running Amass passive enumeration..."
    amass enum -list -config $CONFIG/amass.ini
    amass enum -passive -d $1 -config $CONFIG/amass.ini -o ver_pass_1_amass.txt
}

# Passive subdomain enumeration using Subfinder
ver_pass_2_subfinder(){
    echo "[*] Running Subfinder..."
    subfinder -d $1 -all -config /home/ubuntu/.config/subfinder/provider-config.yaml -o ver_pass_2_subfinder.txt
}

# Passive subdomain enumeration using AssetFinder
ver_pass_3_asset(){
    echo "[*] Running AssetFinder..."
    assetfinder --subs-only $1 > ver_pass_3_asset.txt
}

# Passive subdomain enumeration using Findomain
ver_pass_4_findomain(){
    echo "[*] Running Findomain..."
    findomain -t $1 -u ver_pass_4_findomain.txt
}

# Extract subdomains from GAU
ver_pass_5_gau(){
    echo "[*] Running GAU for subdomain extraction..."
    gauplus -t 5 -random-agent -subs $1 | unfurl -u domains | anew ver_pass_5_gau.txt
}

# Extract subdomains from Wayback URLs
ver_pass_6_wayback(){
    echo "[*] Running Wayback URLs for subdomain extraction..."
    waybackurls $1 | unfurl -u domains | sort -u -o ver_pass_6_wayback.txt
}

# Combine all vertical passive results
final_ver_pass(){
    echo "[*] Combining all vertical passive results..."
    cat ver_pass_* | sort -u | tee $1-subdomains.txt
}

# Recursive passive enumeration on frequently occurring subdomains
ver_pass_recur(){
    echo "[*] Running recursive passive enumeration..."
    for sub in $( ( cat subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
        subfinder -d $sub -all -silent | anew -q passive_recursive.txt
        assetfinder --subs-only $sub | anew -q passive_recursive.txt
        amass enum -list -config $CONFIG/amass.ini | amass enum -passive -d $sub | anew -q passive_recursive.txt
        findomain --quiet -t $sub | anew -q passive_recursive.txt
    done
}

# Run all vertical passive reconnaissance
run_vertical_passive(){
    local domain=$1
    echo "[+] Starting Vertical Passive Reconnaissance for: $domain"
    echo "=================================================="
    
    #ver_pass_1_amass $domain
    ver_pass_2_subfinder $domain
    ver_pass_3_asset $domain
    ver_pass_4_findomain $domain
    ver_pass_5_gau $domain
    ver_pass_6_wayback $domain
    final_ver_pass $domain
    
    echo "[+] Vertical Passive Reconnaissance Complete!"
    echo "[+] Results saved in: $domain-subdomains.txt"
}

# ============================================
# HORIZONTAL RECONNAISSANCE
# ============================================

# Discover IP ranges via WHOIS (BGP.he.net and RADB)
hor_1_whois(){
    echo "[*] Running WHOIS for ASN: $1"
    echo "https://bgp.he.net/"
    whois -h whois.radb.net -- "-i origin $1" | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq
}

# Reverse DNS lookup on IP range
hor_2_RevDNS(){
    echo "[*] Running Reverse DNS on IP range: $1"
    echo $1 | mapcidr -silent | dnsx -ptr -resp-only -o horizontal_2_RevDNS.txt
}

# MurmurHash for favicon identification
hor_3_murhash(){
    echo "[*] Running MurmurHash..."
    python3 /Users/thuandao/go/bin/MurMurHash/MurMurHash.py
}

# Run all horizontal reconnaissance
run_horizontal(){
    local asn=$1
    local ip_range=$2
    echo "[+] Starting Horizontal Reconnaissance"
    echo "========================================"
    
    if [ -n "$asn" ]; then
        hor_1_whois $asn
    fi
    
    if [ -n "$ip_range" ]; then
        hor_2_RevDNS $ip_range
    fi
    
    echo "[+] Horizontal Reconnaissance Complete!"
}

# ============================================
# SHARED UTILITY FUNCTIONS
# ============================================

# Probe live HTTP/HTTPS hosts
http_probe(){
    echo "[*] Probing HTTP/HTTPS hosts..."
    cat $1-subdomains.txt | httpx -silent | tee $1-httpx.txt
}

# Fetch URLs from multiple sources
fetch_url(){
    echo "[+] Fetching URLs from multiple sources..."
    
    echo "[*] Running katana..."
    cat $1-httpx.txt | katana -list $1-httpx.txt -silent -jc -kf all -d 3 -fs rdn -c 30 | grep -Eo "https?://([a-z0-9]+[.])*$1.*" | tee katana.txt
    
    echo "[*] Running GAU..."
    cat $1-httpx.txt | gau --threads 60
    
    echo "[*] Running hakrawler..."
    cat $1-httpx.txt | httpx -silent | hakrawler -subs -u | grep -Eo "https?://([a-z0-9]+[.])*$1.*"
    
    echo "[*] Running waybackurls..."
    cat $1-httpx.txt | waybackurls | grep -Eo "https?://([a-z0-9]+[.])*$1.*"
    
    echo "[*] Running gospider..."
    cat $1-httpx.txt | gospider -S $1-httpx.txt --js -d 2 --sitemap --robots -w -r -t 30 | grep -Eo "https?://([a-z0-9]+[.])*$1.*"
}

# Apply GF patterns for vulnerability detection
gf_pattern() {
    local urls=("$@")
    local host

    # Determine host from provided URLs
    if [ -n "${self_domain_name}" ]; then
        host="${self_domain_name}"
    else
        host=$(echo "${urls[0]}" | awk -F[/:] '{print $4}')
    fi

    local host_regex="https?://([a-z0-9]+[.])*${host}.*"

    # Define the default gf patterns
    DEFAULT_GF_PATTERNS=(
        'debug_logic'
        'idor'
        'interestingEXT'
        'interestingparams'
        'interestingsubs'
        'lfi'
        'rce'
        'redirect'
        'sqli'
        'ssrf'
        'ssti'
        'xss'
    )

    echo "[*] Applying GF patterns..."
    for pattern in "${DEFAULT_GF_PATTERNS[@]}"; do
        gf "$pattern" gf_pattern.txt | grep -Eo "$host_regex"
    done
}

# Directory and file fuzzing
dir_file_fuzz(){
    echo "[*] Starting directory/file fuzzing..."
    ffuf -w $1 -e html,php,git,yaml,conf,cnf,config,gz,env,log,db,mysql,bak,asp,aspx,txt,conf,sql,json,yml,pdf -recursion -recursion-depth 2 -t 30 -fr -ac -u $2 -mc 200,301,302,401,403
}

# Port scanning
scan_port(){
    echo "[*] Scanning ports..."
    naabu -json -exclude-cdn -list $1-subdomains.txt -top-ports 1000 -c 30 -rate 1500 -timeout 5000 -silent
}

# Crawl and gather HTTP information
craw_http(){
    echo "[*] Crawling HTTP endpoints..."
    httpx -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent -t 30 -json -l $1-subdomains.txt -silent -fr | grep -v "context deadline exceeded" | grep -v "no address found for host" | grep -Fv ""
}

# ============================================
# MAIN EXECUTION
# ============================================

# Usage function
usage(){
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d DOMAIN       Target domain for vertical passive recon"
    echo "  -a ASN          ASN number for horizontal recon"
    echo "  -i IP_RANGE     IP range for horizontal recon"
    echo "  -v              Run vertical passive reconnaissance only"
    echo "  -h              Run horizontal reconnaissance only"
    echo "  -f              Run full reconnaissance (vertical + utilities)"
    echo ""
    echo "Examples:"
    echo "  $0 -d example.com -v                    # Vertical passive recon"
    echo "  $0 -a AS15169 -h                        # Horizontal recon with ASN"
    echo "  $0 -d example.com -f                    # Full recon workflow"
    echo "  $0 -a AS15169 -i 192.168.1.0/24 -h      # Horizontal with ASN and IP range"
}

# Parse command line arguments
while getopts "d:a:i:vhf" opt; do
    case $opt in
        d) DOMAIN=$OPTARG ;;
        a) ASN=$OPTARG ;;
        i) IP_RANGE=$OPTARG ;;
        v) MODE="vertical" ;;
        h) MODE="horizontal" ;;
        f) MODE="full" ;;
        *) usage; exit 1 ;;
    esac
done

# Execute based on mode
case $MODE in
    vertical)
        if [ -z "$DOMAIN" ]; then
            echo "[!] Error: Domain required for vertical recon (-d)"
            usage
            exit 1
        fi
        run_vertical_passive $DOMAIN
        ;;
    horizontal)
        if [ -z "$ASN" ] && [ -z "$IP_RANGE" ]; then
            echo "[!] Error: ASN (-a) or IP range (-i) required for horizontal recon"
            usage
            exit 1
        fi
        run_horizontal $ASN $IP_RANGE
        ;;
    full)
        if [ -z "$DOMAIN" ]; then
            echo "[!] Error: Domain required for full recon (-d)"
            usage
            exit 1
        fi
        echo "[+] Starting Full Reconnaissance Workflow"
        echo "==========================================="
        run_vertical_passive $DOMAIN
        http_probe $DOMAIN
        fetch_url $DOMAIN
        #scan_port $DOMAIN
        #craw_http $DOMAIN
        echo "[+] Full Reconnaissance Complete!"
        ;;
    *)
        usage
        exit 1
        ;;
esac
