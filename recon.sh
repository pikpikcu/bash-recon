#!/bin/bash


if [[ $# -eq 0 ]]; 
then
   echo
   echo "+--------------------------------------+"
   echo "|        Recon Bash Scripting          |"
   echo "|   Code By: Ari Sec                   |"
   echo "|   github: @3xploit-db                |"
   echo "+--------------------------------------+"
   echo "Usage: ./script.sh site.com"
   echo 
   exit 0
fi
echo 
echo "[+] Check ASN..."
whois -h whois.cymru.com $(dig +short $1)
echo
mkdir subdo
#run=$1
if [[ -d "subdo" ]]; then
	echo "[+] Check Subdomains..."
	assetfinder --subs-only $1 >> subdo/subdomains.txt
fi
sort -u subdo/subdomains.txt -o subdo/domains.txt
#echo "[+] Done Save Output: subdo/domains.txt"
mkdir live_subdo
if [[ -d "live_subdo" ]]; then
    echo "[+] Check Live Subdomains..."
    cat subdo/domains.txt | sort -u | httprobe -s -p https:443 | tr -d ":443" | tee -a  >> live_subdo/https.txt
else
    cat subdo/domains.txt | sort -u | httprobe -s -p http:80 | tr -d ":80" | tee -a  >> live_subdo/http.txt
fi
#echo "[+] Done Save Output: live_subdo/https.txt"
mkdir sucses
if [[ -d "sucses" ]]; 
then
    cat live_subdo/https.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> sucses/https.txt
else
    cat live_subdo/http.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> sucses/http.txt
fi
#echo "[+] Done Saved Output: sucses/https.txt"
mkdir dir_response
if [[ -d "dir_response" ]]; then
    echo "[+] Check Status Response..."
    cat sucses/https.txt | assetfinder | hakrawler -plain | hakcheckurl | grep -v 404 >> dir_response/dir_https.txt
else
    cat sucses/http.txt | assetfinder | hakrawler -plain | hakcheckurl | grep -v 404 >> dir_response/dir_http.txt
fi
echo "[+] Done Saved Output: dir_response/dir_https.txt"
echo "[+] Get All urls..."
echo "[+] Wait...(10/30m)"
cat sucses/https.txt | getallurls -subs | concurl -c 20 -- -s -L -o /dev/null -k -w '%{https_code},%{size_download}' | tee -a >> out.txt
if [[ -d "file" ]]; then
  cat sucses/http.txt | getallurls -subs | concurl -c 20 -- -s -L -o /dev/null -k -w '%{http_code},%{size_download}' | tee -a >> out1.txt
  else
     echo "[+] http.txt Not Founds..."
fi

mkdir nmap
if [[ -d "nmap" ]]; then
    echo "[+] Start nmap..."
    nmap -v --reason -iL sucses/https.txt -T5 -Pn -oG nmap/nmap.grep -p- | tee -a >> nmap/nmap-log.txt
else
   echo "[+] Start nmap..."
   nmap -v --reason -iL sucses/http.txt -sV -oG nmap/nmap.grep -p- | tee -a >> nmap/nmap-log.txt
fi
egrep -v "^#|Status: Up" nmap/nmap.grep | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p' | awk -F, '{split($0,a," "); printf "%-20s" , a[1], NF}' | sort -k 5 -g >> nmap/nmap_ip.txt

echo "[+] Start Scanning Vulnerabilty..."
echo "[+] Wait...   (10/30m)"
nmap -A --reason --script vuln -iL nmap/nmap_ip.txt -T5 -oG nmap/nmap_vuln.grep -p- | tee -a >> nmap_log_vuln.txt
# Check Host and Open Port
egrep -v "^#|Status: Up" nmap/nmap.grep | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p' | awk '{print "Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s \n" , v[2], v[3], v[1], v[5]}; a=""}' | tee -a >> nmap/nmap_reslute_ip.txt
# Check Service Port
egrep -v "^#|Status: Up" nmap/nmap_vuln.grep | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | sort -n | uniq -c | sort -k 1 -r | head -n 10 | tee -a >> nmap/nmap_reslute_port.txt
# Check top service 
egrep -v "^#|Status: Up" nmap/nmap_vuln.grep | cut -d' ' -f2,4- | tr ',' '\n' | sed -e 's/^[ \t]*//' | awk -F '/' '{print $5}' | grep -v "^$" | sort | uniq -c | sort -k 1 -nr | tee -a >> nmap/nmap_resulte_service.txt




