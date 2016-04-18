#!/usr/bin/env python
"""
parse the raw data from REVELIO tests that ran in the MICROWORKERS:
table header:
boxid, revelio_type, timestamp, local_IP, upnp_wan_ip, STUN, trace_packetsize, traceroute_results

--first line is the traceroute to the mapped address (using 100 bytes packets)
-- example:
3f6eb30ced2211e5aefa90b11c304ecd,
CGNATDETECT,
1458318715.0,
192.168.1.132,
"upnp 87.222.194.220",
"stun 87.222.194.220:50382",
100,
"(null)|Tracing route to 87.222.194.220 with TTL of 16:|(null)| 1  1ms    87.222.194.220|(null)|Traceroute complete.|"


--the rest of the lines are traceroutes to 4.69.202.89, using 21 different packet sizes
-- example for 120bytes packet:
3f6eb30ced2211e5aefa90b11c304ecd, #uuid assigned by the webapp 
CGNATDETECT, # should have here the version of Revelio that ran (e.g., Revelio-v3.1 [microworkers] ) 
1458318715.0,
192.168.1.132,
"upnp 87.222.194.220",
"stun 87.222.194.220:50382",
120,
"(null)|Tracing route to 4.69.202.89 with TTL of 16:|
(null)| 1  1ms    192.168.1.1| 2  37ms   87.222.192.1| 
3  36ms   10.255.9.254| 4  81ms   212.106.217.106| 
5  38ms   212.106.217.105| 6  39ms   193.251.255.4| 
7  37ms   193.251.242.115| 8  57ms   193.251.255.82|
 9  74ms   4.69.210.233|10  81ms   4.69.158.58|
 11  103ms  4.69.201.205|12  74ms   4.69.202.89|
 (null)|Traceroute complete.|"
"""

### in version 5.4 we address the numerous inconsistencies that we findin the data: e.g., some probes do not run all the 21 acket sizes 

import sys, re
from netaddr import *
from pandas import *
import pandas as pd
from scipy import *
from numpy import *
from matplotlib import *
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit
from scipy.stats import linregress
import statsmodels.api as sm
from math import *
import sqlite3 # use this to use as input the sqlite file from the webapp
from optparse import OptionParser

dslite = IPNetwork("192.0.0.0/29")
sharedIP = IPNetwork("100.64.0.0/10")
private1 = IPNetwork("192.168.0.0/16")
private2 = IPNetwork("10.0.0.0/8")
private3 = IPNetwork("172.16.0.0/12")


# the device with the highest number of repetitions (1738) for Revelio is 
# 61d50f9eed6911e5aab390b11c304ecd (MAC Address: 54-E6-FC-81-38-5E) 

class Device(object):
  def __init__(self, boxid):
      self.boxid = boxid # the uuid mapped to the MAC address of the device
      self.revelio = {} # the results of the revelio test (which we have in the Revelio class as functions)
                        # this is in the form of a dict
      self.nat444 = None # the results for the presence of nat444 [yes/no/inconclusive]
      # self.provider = {} # the ISP that provides the Globally Routable Address (public mapped address)

  def __str__(self):
      return "For Device with ID: %u, Revelio tests found NAT444 presence in the ISP: %u" % (self.boxid, self.nat444)

# we include here the discovery tests
# the tests we perform in Revelio use the following information: local_ip, gra, upnp, pathchar, trace_gra, shared_ip, private_ip 
#TODO: the output should be stored in the dabase, as a part of the flask webapp
class Revelio(object):
  def __init__(self, box_id, local_ip, gra, upnp, pathchar, trace_gra, shared_ip, private_ip):
      #self.boxid = boxid # this is the uuid of the devide running Revelio
      self.local_ip = local_ip # the local IP address of the device running the Revelio client (it can be a set of interfaces and IP addresses)
      self.gra = gra # the Globally Routable Address
      self.upnp = upnp # the address retrieved with UPnP on the WAN-facing interface of the CPE connected to the Revelio client
      self.pathchar = pathchar # the location of the access link reported to the Device running Revelio
      self.trace_gra = trace_gra # number of hops replying to the traceroute to the GRA
      self.shared_ip = shared_ip # the shared_ips we detect in the traceroute to the fix target in Level3
      self.private_ip = private_ip # the private_ips we detect in the traceroute to the fix target in Level3

# we define the Revelio tests in the following, based on the information we get from each device running the Revelio client

  # this test verifies whether the device running Revelio is behind a NAT
  def NAT_test():
      return 1
  # this test verifies if the GRA is configured by a device after the access link (i.e., in the access network of the ISP)
  
  def Traceroute_GRA():
      return 1

  # this test compares the GRA to the IP address on the WAN-facing interface of the CPE connecte to the device running Revelio
  # if the two IPs match, there is no CGN
  # if the two IPs don't match and the access link is between them, there is a CGN
  def UPnP_GRA():
      return 1

  # this test checks the presence of shared IP addresses after the access link (i.e., in the access network of the ISP)
  def SharedIPs_in_ISP():
      return 1

  # this test checks the presence of private IP addresses after the access link (i.e., in the access network of the ISP)
  def PrivateIPs_in_ISP():
      return 1


# parse the output of a single traceroute trace - {(packet_size): {(hop_nr, IP): (rtt)} } 
# 376,"(null)|Tracing route to 4.69.202.89 with TTL of 16:|(null)| 1  2ms    192.168.1.1| 2  40ms   87.222.192.1|
def parse_traceroute(trace):
  trace_rtt = {}
  trace_IPs = {}
  for i in trace.index:
    packet_size = trace.trace_packetSize[i]
    traceroute = trace.traceroute_result[i].split("|")
    if packet_size not in trace_rtt:
      trace_rtt[packet_size] = dict()
      for hop in traceroute[3:-1]: # first three fields are irrelevant
        hop_nr = hop.split()[0] # hop number
        if "Request timed out." not in hop:
          hop_ip = hop.split()[2] # the hop IP
          hop_rtt = hop.split()[1].split("ms")[0] # the RTT in ms
        else:
          hop_ip = ""
          hop_rtt = -1

        if hop_nr not in trace_rtt[packet_size]:
          trace_rtt[packet_size][hop_no] = ()
          trace_rtt[packet_size][hop_no].add(hop_rtt)
        else:
          trace_rtt[packet_size][hop_no].add(hop_rtt)
    else:
      for hop in traceroute[3:-1]: # first three fields are irrelevant
        hop_nr = hop.split()[0] # hop number
        if "Request timed out." not in hop:
          hop_ip = hop.split()[2] # the hop IP
          hop_rtt = hop.split()[1].split("ms")[0] # the RTT in ms
        else:
          hop_ip = ""
          hop_rtt = -1

        if hop_nr not in trace_rtt[packet_size]:
          trace_rtt[packet_size][hop_no] = ()
          trace_rtt[packet_size][hop_no].add(hop_rtt)
        else:
          trace_rtt[packet_size][hop_no].add(hop_rtt)


  return trace_rtt, trace_IPs

# run the pathchar algorithm on all the traceroutes we get from device running Revelio
def run_pathchar(traceroutes):
    access_link = -1 # the position of the access link reported to the device running Revelio
                    # -1 = the access link cannot be detected
                    # 0 = the access link is between the device running the Revelio client and the next hop
                    # 1 = the access link is after the first hop from the device running the Revelio client
                    # 2 = the access link is after the 2nd hop from the device running the Revelio client
                    # i = the access link is after the i-th hop from the device running the Revelio client
    return access_link

# parse the raw Revelio data from a single device (identified by a uuid) to out put a Revelio object
def run_Revelio_for_device(data_uuid, device):
    # the header of the input file: boxid,revelio_type,timestamp,local_IP,IGD,STUN_mapped,trace_packetSize,traceroute_result

    if options.verbose:
        print "Revelio ran on this device for " + str(len(list(data_uuid.timestamp.unique()))) + " times."
    nr_runs = len(list(data_uuid.timestamp.unique()))
    local_ip = data_uuid.local_IP.unique() 
    upnp_output = data_uuid.IGD.unique()
    upnp = []
    for res in upnp_output:
      if "upnp " in res:
        wan_ip = res.split(" ")[1]
        if wan_ip not in upnp:
          upnp.append(wan_ip)
      elif res == "noIGD":
        if options.verbose:
          print "The device is not connected to an IGD [UPnP is not (always) supported by the CPE]"

    stun_output = data_uuid.STUN_mapped.unique()
    stun = [] # the set of GRAs we retrieve
    for res in stun_output:
      gra = res.split(" ")[1].split(":")[0] # this is the GRA mapped to the device running the Revelio client
      if gra not in stun:
        stun.append(gra)

    data_trace_GRA = data_uuid[data_uuid.trace_packetSize == 100].traceroute_result
    trace_GRA = parse_traceroute(data_trace_GRA)

    data_traceroute_L3 = data_uuid[data_uuid.trace_packetSize > 100, ( "trace_packetSize","traceroute_result")]
    traceroute_L3 = parse_traceroute(data_traceroute_L3)

    revelio_state =  Revelio(local_ip, gra, upnp, pathchar, trace_gra, shared_ip, private_ip)
    device.revelio = revelio_state

# this is the function that checks the results of the Revelio Discovery tests, compares them and gives the result
# we then store this results in the device.nat444 field of the Device object 
def run_Revelio_discovery(device):
    return 1


#TODO: add an option to read the input raw data from an sqlite file (e.g., leone.db)
#usage = "usage: %prog [options] arg"
parser = OptionParser()

parser.add_option("-i", "--input", dest="input_data",
                  help="Read raw Revelio input in CSV format from FILE. This is a required parameter.", metavar="FILE")
parser.add_option("-o", "--output", dest="out_file",
                  help="Write NAT Revelio results of the discovery phase to FILE", metavar="FILE")
parser.add_option("-f", "--file", dest="parsed_file", 
                  help="Write Revelio parsed results to FILE",  metavar="FILE")
parser.add_option("-v", "--verbose", default=True,
                  help="Output parsing steps info to stdout [default]", action="store_true", dest="verbose")
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=False,
                  help="Don't print status messages to stdout")
(options, args) = parser.parse_args()
if not options.input_data:
    parser.print_help()
    parser.error("Incorrect number of arguments: we need an input filename for raw Revelio results!")
else:
  input_data = options.input_data
if not options.out_file:
    out_file = "revelio.out"
else:
    out_file = options.out_file
if not options.parsed_file:
    parsed_file = "revelio.parsed"
else:
    parsed_file = options.parsed_file
   

if options.verbose:
    print "Parsing Revelio raw results from file " + str(input_data) 
data = pd.read_csv(input_data) # we read the data from a CSV file 
                               # the header of the input file: 
                               # boxid,revelio_type,timestamp,local_IP,IGD,STUN_mapped,trace_packetSize,traceroute_result
                               # this comes from the database schema we defined to store the results of the Revelio client
# for each boxid in the database, we need to run the same detection
for uuid in data.boxid.unique():
    device = Device(uuid)
    #separate the subset of Revelio results coming from a single device 
    if options.verbose:
        print "Parsing Revelio results from device with uuid " + str(uuid)
    data_uuid = data[data.boxid == uuid]
    
    # parse all the raw Revelio data we collect from the device
    run_Revelio_for_device(data_uuid, device)
    run_Revelio_discovery(device)





# if __name__ == '__main__':     #only when run from cmd line
#     main()
