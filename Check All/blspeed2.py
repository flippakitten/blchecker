#Checks all IP addresses against Known black lists and outputs them to a file called blcheckResults.txt
from multiprocessing import Process
import dns.resolver
import sys

bls = ["0spam.fusionzero.com","0spamtrust.fusionzero.com","0spam-killlist.fusionzero.com","0spamurl.fusionzero.com","uribl.zeustracker.abuse.ch","ipbl.zeustracker.abuse.ch","rbl.abuse.ro","uribl.abuse.ro","spam.dnsbl.anonmails.de","list.anonwhois.net","dnsbl.anticaptcha.net","dnsbl6.anticaptcha.net","orvedb.aupads.org","rsbl.aupads.org","aspews.ext.sorbs.net","dnsbl.aspnet.hu","ips.backscatterer.org","b.barracudacentral.org","bb.barracudacentral.org","list.bbfh.org","l1.bbfh.ext.sorbs.net","l2.bbfh.ext.sorbs.net","l3.bbfh.ext.sorbs.net","l4.bbfh.ext.sorbs.net","all.dnsbl.bit.nl","bitonly.dnsbl.bit.nl","blacklist.netcore.co.in","netscan.rbl.blockedservers.com","rbl.blockedservers.com","spam.rbl.blockedservers.com","list.blogspambl.com","bsb.empty.us","bsb.spamlookup.net","query.bondedsender.org","plus.bondedsender.org","dul.dnsbl.borderware.com","blacklist.sci.kun.nl","whitelist.sci.kun.nl","cbl.anti-spam.org.cn","cblplus.anti-spam.org.cn","cblless.anti-spam.org.cn","cdl.anti-spam.org.cn","cml.anti-spam.org.cn","cbl.abuseat.org","dnsbl.cyberlogic.net","bogons.cymru.com","v4.fullbogons.cymru.com","tor.dan.me.uk","torexit.dan.me.uk","ex.dnsbl.org","in.dnsbl.org","rbl.dns-servicios.com","dnsbl.mcu.edu.tw","dnsbl.net.ua","dnsbl.othello.ch","dnsbl.rv-soft.info","dnsblchile.org","dnsrbl.org","vote.drbl.caravan.ru","work.drbl.caravan.ru","vote.drbldf.dsbl.ru","work.drbldf.dsbl.ru","vote.drbl.gremlin.ru","work.drbl.gremlin.ru","bl.drmx.org","dnsbl.dronebl.org","rbl.efnet.org","rbl.efnetrbl.org","tor.efnet.org","bl.emailbasura.org","rbl.fasthosts.co.uk","fnrbl.fast.net","forbidden.icm.edu.pl","88.blocklist.zap","hil.habeas.com","accredit.habeas.com","sa-accredit.habeas.com","hul.habeas.com","sohul.habeas.com","dnsbl.cobion.com","spamrbl.imp.ch","wormrbl.imp.ch","dnsbl.inps.de","dnswl.inps.de","rbl.interserver.net","rbl.iprange.net","iadb.isipp.com","iadb2.isipp.com","iddb.isipp.com","wadb.isipp.com","whitelist.rbl.ispa.at","mail-abuse.blacklist.jippg.org","dnsbl.justspam.org","dnsbl.kempt.net","spamlist.or.kr","bl.konstant.no","admin.bl.kundenserver.de","relays.bl.kundenserver.de","schizo-bl.kundenserver.de","spamblock.kundenserver.de","worms-bl.kundenserver.de","spamguard.leadmon.net","rbl.lugh.ch","dnsbl.madavi.de","service.mailblacklist.com","service.mailwhitelist.com","blacklist.mailrelay.att.net","bl.mailspike.net","rep.mailspike.net","wl.mailspike.net","z.mailspike.net","bl.mav.com.br","cidr.bl.mcafee.com","rbl.megarbl.net","dnsbl.forefront.microsoft.com","bl.mipspace.com","combined.rbl.msrbl.net","images.rbl.msrbl.net","phishing.rbl.msrbl.net","spam.rbl.msrbl.net","virus.rbl.msrbl.net","web.rbl.msrbl.net","relays.nether.net","trusted.nether.net","unsure.nether.net","ix.dnsbl.manitu.net","no-more-funn.moensted.dk","wl.nszones.com","dyn.nszones.com","sbl.nszones.com","bl.nszones.com","ubl.nszones.com","blacklist.mail.ops.asp.att.net","blacklist.sequoia.ops.asp.att.net","spam.pedantic.org","pofon.foobar.hu","ispmx.pofon.foobar.hu","uribl.pofon.foobar.hu","bad.psky.me","psbl.surriel.com","whitelist.surriel.com","all.rbl.jp","dyndns.rbl.jp","short.rbl.jp","url.rbl.jp","virus.rbl.jp","rbl.rbldns.ru","rbl.schulte.org","rbl.talkactive.net","access.redhawk.org","eswlrev.dnsbl.rediris.es","mtawlrev.dnsbl.rediris.es","abuse.rfc-clueless.org","bogusmx.rfc-clueless.org","dsn.rfc-clueless.org","elitist.rfc-clueless.org","fulldom.rfc-clueless.org","postmaster.rfc-clueless.org","whois.rfc-clueless.org","dnsbl.rizon.net","dynip.rothen.com","dnsbl.rymsho.ru","rhsbl.rymsho.ru","all.s5h.net","public.sarbl.org","rhsbl.scientificspam.net","bl.scientificspam.net","reputation-domain.rbl.scrolloutf1.com","reputation-ip.rbl.scrolloutf1.com","reputation-ns.rbl.scrolloutf1.com","tor.dnsbl.sectoor.de","exitnodes.tor.dnsbl.sectoor.de","query.senderbase.org","sa.senderbase.org","bl.score.senderscore.com","score.senderscore.com","singular.ttk.pte.hu","dnsbl.sorbs.net","problems.dnsbl.sorbs.net","proxies.dnsbl.sorbs.net","relays.dnsbl.sorbs.net","safe.dnsbl.sorbs.net","nomail.rhsbl.sorbs.net","badconf.rhsbl.sorbs.net","dul.dnsbl.sorbs.net","zombie.dnsbl.sorbs.net","block.dnsbl.sorbs.net","escalations.dnsbl.sorbs.net","http.dnsbl.sorbs.net","misc.dnsbl.sorbs.net","smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net","rhsbl.sorbs.net","spam.dnsbl.sorbs.net","recent.spam.dnsbl.sorbs.net","new.spam.dnsbl.sorbs.net","old.spam.dnsbl.sorbs.net","web.dnsbl.sorbs.net","korea.services.net","geobl.spameatingmonkey.net","backscatter.spameatingmonkey.net","badnets.spameatingmonkey.net","bl.spameatingmonkey.net","fresh.spameatingmonkey.net","fresh10.spameatingmonkey.net","fresh15.spameatingmonkey.net","netbl.spameatingmonkey.net","uribl.spameatingmonkey.net","urired.spameatingmonkey.net","singlebl.spamgrouper.com","netblockbl.spamgrouper.to","all.spam-rbl.fr","bl.spamcannibal.org","bl.spamcop.net","_vouch.dwl.spamhaus.org","pbl.spamhaus.org","sbl.spamhaus.org","sbl-xbl.spamhaus.org","swl.spamhaus.org","xbl.spamhaus.org","zen.spamhaus.org","feb.spamlab.com","rbl.spamlab.com","all.spamrats.com","dyna.spamrats.com","noptr.spamrats.com","spam.spamrats.com","spamsources.fabel.dk","bl.spamstinks.com","dul.pacifier.net","bl.suomispam.net","gl.suomispam.net","multi.surbl.org","srn.surgate.net","dnsrbl.swinog.ch","uribl.swinog.ch","st.technovision.dk","dob.sibl.support-intelligence.net","dnsbl.tornevall.org","r.mail-abuse.com","q.mail-abuse.com","rbl2.triumf.ca","wbl.triumf.ca","truncate.gbudb.net","dnsbl-0.uceprotect.net","dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net","ubl.unsubscore.com","black.uribl.com","grey.uribl.com","multi.uribl.com","red.uribl.com","white.uribl.com","free.v4bl.org","virbl.dnsbl.bit.nl","dnsbl.webequipped.com","ips.whitelisted.org","blacklist.woody.ch","uri.blacklist.woody.ch","db.wpbl.info","bl.blocklist.de","dnsbl.zapbl.net","rhsbl.zapbl.net"] 

def checkIPAddresses(bl):
    count = 0
    with open('gemIPs.txt') as gemFile:
	    for line in gemFile:
	        string = line
	        ipAddresses = string.split(",")
	        for ip in ipAddresses:
	        	myIP = ip
		        try:
		            count += 1
		            my_resolver = dns.resolver.Resolver()
		            query = '.'.join(reversed(str(myIP).split("."))) + "." + bl
		            answers = my_resolver.query(query, "A")
		            answer_txt = my_resolver.query(query, "TXT")
		            print '%s: %s LISTED %s (%s: %s)' %(count,myIP, bl, answers[0], answer_txt[0])
		            with open("blcheckResults.txt", "a") as results:
		                #results.write(myIP + "," + bl + "," + answers + "," + answer_txt + "\n")
		                results.write(str(myIP) + "," + str(bl) + "," + str(answers[0]) + "," + str(answer_txt[0]) + "\n")
		     	except dns.resolver.NXDOMAIN:
		            print '%s: %s fine in %s' %(count,myIP, bl)
		        except dns.resolver.NoAnswer:
		            print '%s: No Answer from %s' %(count,bl)
		        except dns.exception.Timeout:
		            print '%s: Timeout to %s'  %(count,bl)
		        except dns.resolver.NoNameservers:
		            print '%s: No name server for %s'  %(count,bl)

if __name__ == '__main__':
	for bl in bls:
		Process(target=checkIPAddresses, args=(bl,)).start()
    			

    
    
    			