#Python script for parsing data and converting it to JSON (probably for graylog)
#(C) Dr. Kyle Cronin, Dakota State University

__author__ = "Kyle Cronin"
__copyright__ = "Copyright (C) 2021 Kyle Cronin"
__license__ = "GNU GPL"
__version__ = "1.1"
#1.1 Changes-- added a couple lines that handle the USB radio taking a dump. We just blindly reset it and hope for the best. 

import threading
import os, time
import random
from scapy.all import *
import logging
import json
import traceback
from time import sleep

logger = 0

channelLookup ={
	2412:1,
	2417:2,
	2422:3,
	2427:4,
	2432:5,
	2437:6,
	2442:7,
	2447:8,
	2452:9,
	2457:10,
	2462:11,
	2467:12,
	2472:13,
	2484:14,
	2484:14,
	5180:36,
	5200:40,
	5220:44,
	5240:48,
	5260:52,
	5280:56,
	5300:60,
	5320:64,
	5500:100,
	5520:104,
	5540:108,
	5560:112,
	5580:116,
	5600:120,
	5620:124,
	5640:128,
	5660:132,
	5680:136,
	5700:140,
	5720:144,
	5745:149,
	5765:153,
	5785:157,
	5805:161,
	5825:165
}

def channelHop(interface, channel): #background thread that hops wifi channels
	os.system('iwconfig %s channel %d' % (interface, channel))

def packetMuncher(frame): #defines the packet type and passes on
	if frame.haslayer(Dot11Beacon): #find Beacons
		processBeacon(frame)
	elif frame.haslayer(Dot11AssoReq):
		processAssocReq(frame)
	elif frame.haslayer(Dot11AssoResp): 
		processAssocResp(frame)
	elif frame.haslayer(Dot11Auth):
		processAuth(frame)
	elif frame.haslayer(Dot11Deauth): 
		processDeauth(frame)
	elif frame.haslayer(Dot11Disas):
		processDissociation(frame)
	elif frame.haslayer(Dot11ProbeReq):
		processProbeReq(frame)
	elif frame.haslayer(Dot11ProbeResp):
		processProbeResp(frame)
	elif frame.haslayer(Dot11WEP):#TODOwep shit
		processDummyPacket(frame)
	else:
		processDummyPacket(frame)


def parseBasicInfo(frame): #parse basic info that we expect to be in all 802.11 frames
	frequency = frame.ChannelFrequency
	signal = frame.dBm_AntSignal
	sender = frame.getlayer(Dot11).addr2
	channel = channelLookup[frequency]

	data = """
	"_channel" : "%s",
	"_frequency" :"%s",
	"_signal" : "%s",
	"_sender" : "%s"
	""" % (channel,frequency,signal,sender)
	return data


def processAuth(frame):
	algorithm = frame.getlayer(Dot11Auth).algo
	seqnum = frame.getlayer(Dot11Auth).seqnum
	status = frame.getlayer(Dot11Auth).status

	data = """
	"short_message" : "auth",
	"_type" : "auth",
	"_algorithm" : "%s",
	"_sequence_number" : "%s",
	"status" : "%s",%s
	""" % (algorithm, seqnum, status, parseBasicInfo(frame))
	sendGelf(data)
	#print(data)


def processAssocResp(frame):
	print(frame.summary)
	status=frame.getlayer(Dot11AssoResp).status
	aid = frame.getlayer(Dot11AssoResp).AID
	capability = frame.getlayer(Dot11AssoResp).cap
	recipient = frame.getlayer(Dot11).addr1

	data = """
	"short_message" : "assocresp",
	"_type" : "assocresp",
	"_recipient" : "%s",
	"_status" : "%s",
	"_aid" : "%s",
	"_capability" : "%s",%s
	""" % (recipient, status, aid, capability, parseBasicInfo(frame))
	sendGelf(data)
	#print(data)


def processAssocReq(frame):
	capability = frame.getlayer(Dot11AssoReq).cap
	listen_interval = frame.getlayer(Dot11AssoReq).listen_interval
	essid= frame.getlayer(Dot11Elt).info.decode("utf-8")
	recipient = frame.getlayer(Dot11).addr1

	data = """
	"short_message" : "assocreq",
	"_type" : "assocreq",
	"_recipient" : "%s",
	"_essid" : "%s",
	"_capability" : "%s",
	"_listen_interval" : "%s", %s
	""" % (recipient, essid,capability, listen_interval, parseBasicInfo(frame))
	sendGelf(data)
	#print(data)


def processDeauth(frame):
	print(frame.summary)
	recipient = frame.getlayer(Dot11).addr1
	reason = frame.getlayer(Dot11Deauth).reason

	data = """
	"short_message" : "deauth",
	"_type" : "deauth",
	"_recipient" : "%s",
	"_reason_code" : "%s",%s
	""" % (recipient,reason,parseBasicInfo(frame))
	sendGelf(data)


def processDissociation(frame):
	print(frame.summary)
	recipient = frame.getlayer(Dot11).addr1
	reason = frame.getlayer(Dot11Disas).reason

	data = """
		"short_message" : "disassoc",
		"type" : "disassoc",
		"_recipient" : "%s",
		"_reason_code" : "%s",%s
	""" % (recipient,reason,parseBasicInfo(frame))
	sendGelf(data)


def processProbeReq(frame):
	essid= frame.getlayer(Dot11Elt,ID=0).info.decode("utf-8")
	if essid=="":
		essid="NULL"

	data = """
	"short_message" : "probe_req",
	"_type" : "probe-req",
	"_essid" : "%s",%s
	""" % (essid, parseBasicInfo(frame))
	sendGelf(data)


def processProbeResp(frame):
	ssid = frame.getlayer(Dot11ProbeResp).info.decode("utf-8")
	recipient = frame.getlayer(Dot11).addr1

	data = """
		"short_message" : "probe-resp",
		"_type" : "probe-resp",
		"_recipient" : "%s",
		"_essid" : "%s",%s
		""" % (recipient,ssid,parseBasicInfo(frame))
	sendGelf(data)


def processBeacon(frame):#process packets that are beacons
	ssid= frame.getlayer(Dot11Elt,ID=0).info.decode("utf-8")
	if ssid=="": 
		ssid="NULL"
	ssidLength = frame.getlayer(Dot11Elt).len
	timestamp = frame.getlayer(Dot11Beacon).timestamp
	beacon_interval = frame.getlayer(Dot11Beacon).beacon_interval
	capability = frame.getlayer(Dot11Beacon).cap
	bssid = frame.getlayer(Dot11).addr2

	data = """
		"short_message" : "beacon",
		"_type" : "beacon",
		"_essid" : "%s",
		"_ssid_length" : "%s",
		"_timestamp" : "%s",
		"_beacon_interval" : "%s",
		"_capability" : "%s", %s
		""" % (ssid,ssidLength,timestamp,beacon_interval,capability,parseBasicInfo(frame))
	sendGelf(data)


def sendGelf(data):
	server= 'http://graylog.ialab.dsu.edu:12201/gelf'

	raw= """
	{
		"version" : "1.1",
		"host" : "WHATS_UR_NAME",%s
	}""" % data
	try:
		jsonPrime = json.loads(raw, strict=False)
		jsonData = json.dumps(jsonPrime)
		curlCommand = """curl -X POST -H 'Content-Type: application/json' -p0 -d '%s' %s """  % (jsonData,server)
		#os.system(curlCommand)

		server= 'http://graylog.ialab.dsu.edu:12201/gelf'
		curlCommand = """curl -X POST -H 'Content-Type: application/json' -p0 -d '%s' %s """  % (jsonData,server)
		os.system(curlCommand)
	except:
		print ("JSON loads or dumps FAILURE")
		traceback.print_exc()
		print (raw)



def processDummyPacket(frame):#process a packet that we didn't identify
	goat=1
	#print ("Meh")

def findInterface():
	for interface in socket.if_nameindex():
		if(str(interface[1])[0:3]) == "wlx":
			return interface[1]
	print ("No wlx interface was found")
	return -1

if __name__ == "__main__":
	#interface = findInterface()
	interface="wlan0"
	#monitorCommand="sudo airmon-ng start %s" % interface
	command = "sudo ifconfig %s down" %interface
	os.system(command)
	command = "sudo iwconfig %s mode monitor" %interface
	os.system(command)

	command = "sudo ifconfig %s up" %interface
	os.system(command)


	while True:
		rando = int (random.random()*14)

		try:
			sniff(iface=interface,prn=packetMuncher, store=0, timeout=5)
			rando = int (random.random()*14)
			channelHop(interface, rando)

		except Exception as e:
			print ( e ) 
			print ("Except happeneD")
		#hail mary-- we're guessing we hit an exception b/c the interface died. Just reset it. This isn't the smartest way, but it works for now. 
		#os.system("usbreset | grep -i wlan | awk '{ print $2 }' | xargs -I{} usbreset {}")
		#sleep(2)
		#os.system(f'ifconfig {interface} down; iwconfig {interface} mode monitor; ifconfig {interface} up')




