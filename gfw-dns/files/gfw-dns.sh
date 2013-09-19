#!/bin/sh

. /lib/functions.sh

rulefile=/var/g.firewall.user

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

echo "iptables -N protectdns" >> $rulefile.tmp 

for ip in $badip ; do
	hexip=$(printf '%02X ' ${ip//./ }; echo)
	echo "iptables -I protectdns -m string --algo bm --hex-string \"|$hexip|\" --from 60 --to 500  -j DROP" >> $rulefile.tmp 
done

echo "iptables -I protectdns -m u32 --u32 \"4 & 0x1FFF = 0 && 0 >> 22 & 0x3C @ 8 & 0x8000 = 0x8000 && 0 >> 22 & 0x3C @ 14 = 0\" -j DROP" >> $rulefile.tmp
echo "iptables -I INPUT -p udp --sport 53 -j protectdns" >> $rulefile.tmp
echo "iptables -I FORWARD -p udp --sport 53 -j protectdns" >> $rulefile.tmp

if [[ -s $rulefile ]] ; then
        grep -Fvf $rulefile $rulefile.tmp > $rulefile.action
        cat $rulefile.action >> $rulefile
else
        cp $rulefile.tmp $rulefile
        cp $rulefile.tmp $rulefile.action
fi

. $rulefile.action
rm $rulefile.tmp
rm $rulefile.action
}

delrules()
{
iptables -D INPUT -p udp --sport 53 -j protectdns 2>/dev/null
iptables -D FORWARD -p udp --sport 53 -j protectdns 2>/dev/null
iptables -F protectdns 2>/dev/null
iptables -X protectdns 2>/dev/null
rm $rulefile
}
