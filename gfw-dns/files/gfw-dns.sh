#!/bin/sh

. /lib/functions.sh

addrules()
{
local domains
local loops
local enabled

config_load gfw-dns
config_get_bool enabled general enabled
config_get loops general loops
config_get domains general domains

[ $enabled -eq 0 ] && return

# wait tail has internet connection
while ! ping -W 1 -c 1 8.8.8.8 >&/dev/null; do sleep 30; done

badip=""

querydomain=""
matchregex="^${domains//\ /|^}"
for i in $(seq $loops) ; do
	querydomain="$querydomain $domains"
done

for domain in $domains ; do
	for ip in $(dig +time=1 +tries=1 +retry=0 @$domain $querydomain | grep -E "$matchregex" | grep -o -E "([0-9]+\.){3}[0-9]+") ; do
		if [ -z "$(echo $badip | grep $ip)" ] ; then
			badip="$badip   $ip"
		fi
	done
done

iptables -t mangle -N protectdns 2>/dev/null

for ip in $badip ; do
	hexip=$(printf '%02X ' ${ip//./ }; echo)
	iptables -t mangle -I protectdns -m string --algo bm --hex-string "|$hexip|" --from 60 --to 500  -j DROP
done

iptables -t mangle -D protectdns -m u32 --u32 "4 & 0x1FFF = 0 && 0 >> 22 & 0x3C @ 8 & 0x8000 = 0x8000 && 0 >> 22 & 0x3C @ 14 = 0" -j DROP 2>/dev/null
iptables -t mangle -I protectdns -m u32 --u32 "4 & 0x1FFF = 0 && 0 >> 22 & 0x3C @ 8 & 0x8000 = 0x8000 && 0 >> 22 & 0x3C @ 14 = 0" -j DROP

iptables -t mangle -D INPUT -p udp --sport 53 -j protectdns 2>/dev/null
iptables -t mangle -I INPUT -p udp --sport 53 -j protectdns
iptables -t mangle -D FORWARD -p udp --sport 53 -j protectdns 2>/dev/null
iptables -t mangle -I FORWARD -p udp --sport 53 -j protectdns
}

delrules()
{
iptables -t mangle -D INPUT -p udp --sport 53 -j protectdns 2>/dev/null
iptables -t mangle -D FORWARD -p udp --sport 53 -j protectdns 2>/dev/null
iptables -t mangle -F protectdns 2>/dev/null
iptables -t mangle -X protectdns 2>/dev/null
}
