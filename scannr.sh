#!/bin/bash
## Open Source Tools
##
## https://github.com/darkoperator/dnsrecon
## https://github.com/rastating/joomlavs
## https://github.com/wpscanteam/wpscan
##
## Required Packages: `git curl liblzma-dev libcurl4-openssl-dev libxml2 libxml2-dev python-netaddr python-dnsq libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev patch`
## Change dir to joomlavs then `sudo gem install bundler && bundle install`
## Change dir to wpscan then `sudo gem install bundler && bundle install`
##

rm -f temp/*

cpwd=$(pwd)
fdate=$(date +%Y%m%d_%H%M%S)

clear
echo "Scannr will perform the following: "
echo ""
echo "[*] List all subdomains"
echo "[*] List all cms information"
echo "[*] Wordpress vulnerability scanning"
echo "[*] Joomla vulnerability scanning"
echo ""
read -p "[?] Host: " host
echo ""

##Directory checking/creation for storing files
check_dir()
{
	if [ ! -d reports/ ]; then
		echo "[OK] Creating 'reports' directory"
		mkdir reports/
	fi

	if [ ! -d temp/ ]; then
		echo "[OK] Creating 'temp' directory"
		mkdir temp/
	fi
}

##Host check if alive
##Use curl if icmp is disabled
check_host()
{
	curl --silent --location --insecure "$host" > /dev/null 2>&1
	if [ $? = 0 ]; then
		echo "[OK] Host: \"$host\" is up"
		echo "[+] ------------------"
		echo ""
	else
		echo "[ERR] Host: \"$host\" is unreachable"
		echo "[ERR] Scannr will now exit"
	fi
}

##Subdomain enumeration using dnsrecon
get_subdomain()
{
	echo "[+] Enumerating subdomains of $host"
	echo "[+] -------------------------------"
	sleep 2
	python dnsrecon/dnsrecon.py -d "$host" -t std -g --csv temp/"$host".dns.tmp > /dev/null 2>&1
	if [ $? = 0 ]; then
		mkdir -p reports/"$host"
		grep -Ev 'AAAA,|CNAME,|PTR,|TXT,|MX,|SOA,|Bind,|Type' temp/"$host".dns.tmp | grep -Ev 'AAAA,|CNAME,|PTR,|TXT,|MX,|NS,|SOA,|Bind,|Type' | awk -F 'A,' '{print $2}' | awk -F ',' '{print $1}' | sort | uniq >> reports/"$host"/all.txt
		rm -f temp/"$host".dns.tmp
		sed -i '/^$/d' reports/"$host"/all.txt
		echo "[OK] Generating list of subdomains to reports/\"$host\"/all.txt folder"
		echo ""
	else
		echo "[ERROR] An error occured while writing the report"
		echo "[ERROR] GovScan will now exit"
	fi
}

##CMS detection with curl
##Use head for the first 100 lines of code to speed up cms detection
##Will add drupal cms detection soon
get_cms()
{
	ctr=0
	user_agent="Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-us) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85.8.1";
	if [ -f reports/"$host"/all.txt ]; then
		echo "[+] Checking CMS type"
		echo ""
		while read remote_host; do
		ctr=$((ctr+1))
		curl --silent --location --insecure "$remote_host" --speed-time 10 --user-agent "$user_agent" > /dev/null 2>&1
		if [ $? = 0 ]; then
			curl --silent --location --insecure "$remote_host" --speed-time 10 --user-agent "$user_agent" | grep -Ei 'wp-content|wp-includes' > /dev/null 2>&1
			if [ $? = 0 ]; then
			echo "$remote_host" >> reports/"$host"/wordpress.txt
			curl -I -L "$host" >> reports/"$host".banner.txt > /dev/null 2>&1
			echo "[OK|\"$ctr\"] \"$remote_host\": Wordpress"
			fi
			curl --silent --location --insecure "$remote_host" --speed-time 10 --user-agent "$user_agent" | grep -Ei 'Joomla!|joomla' > /dev/null 2>&1
			if [ $? = 0 ]; then
			echo "$remote_host" >> reports/"$host"/joomla.txt
			curl -I -L "$host" >> reports/"$host".banner.txt > /dev/null 2>&1
			echo "[OK|\"$ctr\"] \"$remote_host\": Joomla"
			fi
			curl --silent --location --insecure "$remote_host" --speed-time 10 --user-agent "$user_agent" | grep -Ei 'Joomla!|joomla|wp-content|wp-includes' > /dev/null 2>&1
			if [ $? = 1 ]; then
			echo "$remote_host" >> reports/"$host"/php.txt
			curl -I -L "$host" >> reports/"$host".banner.txt > /dev/null 2>&1
			echo "[OK|\"$ctr\"] \"$remote_host\": PHP/HTML"
			fi
		else
		echo "$remote_host" >> reports/"$host"/down.txt
			echo "[DOWN|\"$ctr\"] \"$remote_host\": Host is down"
		fi
		done < reports/"$host"/all.txt
		echo ""
	else
		echo "[*] CMS result file not found"
		echo "[+] Skipping CMS detection"
		echo ""
	fi
}

##Wordpress vulnerability scanning with wpscan
scan_wordpress()
{
	if [ -f "$cpwd"/reports/"$host"/wordpress.txt ]; then
		echo "[+] Performing Wordpress Scan"
		echo ""
		cd "$cpwd"/wpscan || return
		while read wpdomain; do
		echo "[+] Scanning: \"$wpdomain\""
		ruby wpscan.rb --url "$wpdomain" --batch --no-banner --threads 4 --random-agent >> ../reports/"$host"/"$wpdomain".wordpress."$fdate".txt
		done < "$cpwd"/reports/"$host"/wordpress.txt
		echo ""
	else
		echo "[+] Wordpress file list not found"
		echo "[+] Skipping Wordpress Scan"
		echo ""
	fi
}

##Joomla vulnerability scanning with joomlavs
scan_joomla()
{
	if [ -f "$cpwd"/reports/"$host"/joomla.txt ]; then
		echo "[+] Performing Joomla Scan"
		echo ""
		cd "$cpwd"/joomlavs || return
		while read jldomain; do
		echo "[+] Scanning: \"$jldomain\""
		ruby joomlavs.rb --url "$jldomain" --no-colour --follow-redirection --scan-all --threads 4 >> ../reports/"$host"/"$jldomain".joomla."$fdate".txt
		done < "$cpwd"/reports/"$host"/joomla.txt
		echo ""
	else
		echo "[+] Joomla file list not found"
		echo "[+] Skipping Joomla Scan"
		echo ""
	fi
}

check_dir
get_subdomain
get_cms
scan_wordpress
scan_joomla
