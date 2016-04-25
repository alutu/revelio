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
private = IPSet([IPNetwork("192.168.0.0/16"), IPNetwork("10.0.0.0/8"), IPNetwork("172.16.0.0/12")])
# private1 = IPNetwork("192.168.0.0/16")
# private2 = IPNetwork("10.0.0.0/8")
# private3 = IPNetwork("172.16.0.0/12")


# the device with the highest number of repetitions (1738) for Revelio is 
# 61d50f9eed6911e5aab390b11c304ecd (MAC Address: 54-E6-FC-81-38-5E) 

class Device(object):
  def __init__(self, uuid):
      self.boxid = uuid # the uuid mapped to the MAC address of the device
      self.revelio = None # the results of the revelio test (which we have in the Revelio class as functions)
                        # this is in the form of a dict
      self.nat444 = None # the results for the presence of nat444 [yes/no/inconclusive]
      # self.provider = None # the ISP that provides the Globally Routable Address (public mapped address)
      # self.country = None

  def __str__(self):
      return "For Device with ID: %u, Revelio found NAT444 presence in the ISP: %u" % (self.boxid, self.nat444)

# we include here the discovery tests
# the tests we perform in Revelio use the following information: local_ip, gra, upnp, pathchar, trace_gra, shared_ip, private_ip 
#TODO: the output should be stored in the dabase, as a part of the flask webapp
class Revelio(object):
  def __init__(self, local_ip, gra, upnp, pathchar, trace_gra, shared_ip, private_ip):
      #self.boxid = boxid # this is the uuid of the devide running Revelio
      self.local_ip = local_ip # the local IP address of the device running the Revelio client (it can be a set of interfaces and IP addresses)
      self.gra = gra # the Globally Routable Address
      self.upnp = upnp # the address retrieved with UPnP on the WAN-facing interface of the CPE connected to the Revelio client
      self.pathchar = pathchar # the location of the access link reported to the Device running Revelio
      self.trace_gra = trace_gra # number of hops replying to the traceroute to the GRA
                                 # have this as a dict -- {number_hops: x, timeout: True/False}
      self.shared_ip = shared_ip # the shared_ips we detect in the traceroute to the fix target in Level3
      self.private_ip = private_ip # the private_ips we detect in the traceroute to the fix target in Level3

# we define the Revelio tests in the following, based on the information we get from each device running the Revelio client

  # this test verifies whether the device running Revelio is behind a NAT
  def NAT_test(self):
      if self.local_ip not in private: #  and self.local_ip not in shared_ip:
        if options.verbose:
          print "There is no NAT in the home network."
        return False # FALSE -- no NAT444
      elif self.local_ip in private:
        if options.verbose:
          print "There is one level of NAT in the home network."
        return True

  # this test verifies if the GRA is configured by a device after the access link (i.e., in the access network of the ISP)
  def Traceroute_GRA(self):
    if self.trace_gra >0:
      if self.trace_gra >= self.pathchar:
        if options.verbose:
          print "NAT444 True: GRA is beyond the access link"
        return True
      else:
        if options.verbose:
          print "NAT444 False: GRA is before the access link."
        return False
    else:
      if options.verbose:
        print "NAT444 inconclusive: we cannot say if there is a NAT444 only from this info"
      return -1 # we cannot say if there is a NAT444 only from this info

  # this test compares the GRA to the IP address on the WAN-facing interface of the CPE connecte to the device running Revelio
  # if the two IPs match, there is no CGN
  # if the two IPs don't match and the access link is between them, there is a CGN
  def UPnP_GRA(self):
      if self.upnp[0] in self.gra:
        if option.verbose:
          print "NAT444 False: The GRA matches the UPnP retrieved address on the CPE."
        return False
      elif self.upnp != "noIGD" and not set(self.gra).intersection(self.upnp) and self.pathchar == 2:
        if option.verbose:
          print "NAT444 True: The GRA does not match the UPnP retrieved address on the CPE, access link immediately after the CPE."
        return True
      elif self.upnp != "noIGD" and not set(self.gra).intersection(self.upnp) and self.pathchar <= self.trace_gra:
        if option.verbose:
          print "NAT444 True: The GRA does not match the UPnP retrieved address on the CPE, access link immediately after the CPE."
        return True
      else:
        if option.verbose:
          print "NAT444 Inconclusive: UPnP not supported and cannot interpret results"
        return -1

  # this test checks the presence of shared IP addresses after the access link (i.e., in the access network of the ISP)
  def SharedIPs_in_ISP(self):
      return self.shared_ip

  # this test checks the presence of private IP addresses after the access link (i.e., in the access network of the ISP)
  def PrivateIPs_in_ISP(self):
      return self.private_ip

# parse the output of the traceroute results coming from a device running revelio 
#     --- {(packet_size): {(hop_nr): (rtt, IP)} } 
# 376,"(null)|Tracing route to 4.69.202.89 with TTL of 16:|(null)| 1  2ms    192.168.1.1| 2  40ms   87.222.192.1|
# this will only parse the traceroute from Windows -- not the one from the SK whiteboxes or the ones from the Android App
# the input _trace_ is a pandas data frame that contains two fields only: [trace_packetSize, traceroute_result]
def parse_trace(trace): 
  trace_rtt = {}
  trace_IPs = {}
  for i in trace.index: # for each run of the traceroute
    packet_size = trace.trace_packetSize[i] # get the packet size
    traceroute = trace.traceroute_result[i].split("|") # get the output per hop of the traceroute
    for hop in traceroute[3:-1]: # first three fields are irrelevant in the output of the windows traceroute
        ttl = ttl.split()[0] # hop number (TTL)
        if "Request timed out." not in hop:
          hop_ip = ttl.split()[2] # the hop IP
          hop_rtt = ttl.split()[1].split("ms")[0] # the RTT in ms
        else:
          hop_ip = None
          hop_rtt = 0
        if ttl not in trace_rtt:
          trace_rtt[ttl] = dict()
          if packet_size not in trace_rtt[ttl]:
            trace_rtt[ttl][packet_size] = set()
            trace_IPs[ttl][packet_size] = set()
            trace_rtt[ttl][packet_size].add(hop_rtt)
            trace_IPs[ttl][packet_size].add(hop_ip)
          else:
            trace_rtt[ttl][packet_size].add(hop_rtt)
            trace_IPs[ttl][packet_size].add(hop_ip)
        else:
          if packet_size not in trace_rtt[ttl]:
            trace_rtt[ttl][packet_size] = set()
            trace_IPs[ttl][packet_size] = set()
            trace_rtt[ttl][packet_size].add(hop_rtt)
            trace_IPs[ttl][packet_size].add(hop_ip)
          else:
            trace_rtt[ttl][packet_size].add(hop_rtt)
            trace_IPs[ttl][packet_size].add(hop_ip)
  return (trace_rtt, trace_IPs) # return two different dictionaries, one for the RTTs per hop and another for the IPs per hop


'''
Run the pathchar algorithm on all the traceroutes we get from device running Revelio
 e.g.: # 376,"(null)|Tracing route to 4.69.202.89 with TTL of 16:|(null)| 1  2ms    192.168.1.1| 2  40ms   87.222.192.1|
 INPUT: parsed traces into a dict of {hop_number:{packet_size:RTT}}
Perform statistical analysis for the RTTs from traceroutes [PATHCHAR]
# run the following per probe and then per TTL:
#  1) minimum filtering
#  2) curve-fitting
#  3) differencing to find the BW and latency values on each link

OUTPUT: position of the access link from the device running the Revelio client: <access_link>
                # the values of the access_link values stand for the following:
                # 0 = the access link cannot be detected
                # i = the access link is after the i-th hop from the device running the Revelio client
'''
def run_pathchar(trace_rtt, uuid):
    SORTTs = dict() # for each TTL and for each packet size, we store the minimum RTT we were able to measure
    slope_intercept = dict() # for each TTL, keep the parameters of the fitted cure
    access_link = 0 # the position of the access link reported to the device running Revelio
    links = [] # store how many links we can parse from the TTL
    if options.verbose:
       print "Running pathchar for device " + str(uuid)
    print "TTL vector: " + str(sort(trace_rtt.keys()))
    for ttl in list(sort(trace_rtt.keys())): # separate TTL: process one TTL value at a time
        ttl_data = trace_rtt[ttl] # select all the traceroute result for all packet lengths with TTL = ttl
        SORTTs[ttl]= dict()
        if options.verbose:
            print " \nRunning pathchar for link [TTL] " + str(ttl)
#1)
        for packet_size in ttl_data.keys():
            if packet_size >100 : # exclude the traceroute to the STUN mapped address which is being done with packet_size = 100
                SORTTs[ttl][packet_size] = min(ttl_data[packet_size])
            else:
                continue 
#2)
        # normally, we should have input for 21 different packet sizes, check that we do, otherwise discard since the fitting cannot be done
        if options.verbose:
          print "Number of packet sizes tested: " + str(len(zip([packet_size for packet_size in SORTTs[ttl]], [SORTTs[ttl][packet_size] for packet_size in SORTTs[ttl]])))
        if len(zip([packet_size for packet_size in SORTTs[ttl]], [SORTTs[ttl][packet_size] for packet_size in SORTTs[ttl]])) >= 19 : 

            probe_ttl_df = DataFrame(SORTTs[ttl].items(), columns = ['packet_size', 'min_rtt'])  

            ##print "Data Frame empty: " + str(len(probe_ttl_df.as_matrix()))
            # check that we do have data to work with
            if len(probe_ttl_df.as_matrix()) > 1:
                linear_model = sm.RLM.from_formula("min_rtt ~ packet_size", data = probe_ttl_df, M=sm.robust.norms.LeastSquares())
                #linear_model = sm.RLM(probe_ttl_df['min_rtt'], probe_ttl_df['packet_size'], M=sm.robust.norms.LeastSquares)
                res = linear_model.fit()
                if options.verbose:
                  try:
                      print res.summary()
                  except:
                      print "Error here!!!"

                slope_intercept[ttl] = [res.params['packet_size'], res.params['Intercept']]
                links.append(ttl)
            else:
              if options.verbose:
                print " No input for pathchar"
              break
            ###plt.plot(probe_ttl_df['packet_size'], probe_ttl_df['min_rtt'], 'o', color = 'k')
            ###plt.plot(probe_ttl_df['packet_size'], res.fittedvalues, '-');

            #ABLine2D(res.params['packet_size'], res.params['Intercept'])

        else:
            if parameters.verbose:
              print " Not enough input to run pathchar: hop did not reply to traceroute"
            slope_intercept[ttl] = [0, 0]

###        plt.xlabel("Packet Size [bytes]")
###        plt.ylabel("RTT [ms]")
###        plt.title("PathChar: Curve Fitting for Probe " + str(probe))
###        plt.show()

#3)
    bw_lat = dict()
    if slope_intercept[1][0]>0: ### we control for values of 0 
        bw = 8/(1000*slope_intercept[1][0])
    else:
        bw = 0
    if slope_intercept[probe, 1][1]>0:
        lat = slope_intercept[probe, 1][1]/2
    else:
        lat = 0
    bw_lat[1] = [bw, lat] # values for TTL = 1 --> the first link
    if options.verbose:
      print "Differentiating to obtain BW and LAT estimates for probe " + str(probe)
      print "TTL vector: " + str(sort(data[data['Probe_ID'] == probe]['TTL'].unique()))
      print " Link 1: BW [Mb] , LAT[ms]: " + str(bw_lat[probe][1])

    for ttl in list(links):
      if ttl+1 < len(list(links)):
# add condition here to take only the non-zero values of the RTT
          if slope_intercept[ttl+1][0] == 0 or slope_intercept[ttl+1][0] == 'nan':
              slope_intercept[ttl+1][0] = slope_intercept[ttl][0]
          if slope_intercept[ttl+1][0] <= slope_intercept[ttl][0]:
            try:
              if (slope_intercept[ttl][0] - slope_intercept[ttl+1][0])/slope_intercept[ttl][0] < 0.5:
                  bw = bw_lat[ttl][0]
              else:
                  bw = 8/(1000*(slope_intercept[ttl+1][0] - slope_intercept[ttl][0]))
            except:
              bw = 0
          else:
              bw = 8/(1000*(slope_intercept[ttl+1][0] - slope_intercept[ttl][0]))

          if slope_intercept[ttl +1][1] == 0 or slope_intercept[ttl +1][1] == 'nan':
              slope_intercept[ttl +1][1] = slope_intercept[ttl][1]
          if slope_intercept[ttl +1][1] <= slope_intercept[ttl][1]:
            try:
              if (slope_intercept[ttl][1] - slope_intercept[ttl+1][1])/slope_intercept[ttl][1] < 0.5:
                  lat = bw_lat[ttl][1]
              else:
                  lat = (slope_intercept[ttl +1][1] - slope_intercept[ttl][1])/2
            except:
              lat = 0
          else:
              lat = (slope_intercept[ttl +1][1] - slope_intercept[ttl][1])/2

          bw_lat[ttl+1] = [bw, lat]    
          if options.verbose:
            print " Link " + str(ttl+1) + ": BW [Mb] , LAT[ms]: " + str(bw_lat[ttl +1])

#4) Detect the access link and the location of the SK Whitebox
    for ttl in bw_lat[probe]:
      try:
        if ttl > 1 and ttl+1 in bw_lat:
            if options.verbose:
              print "TTL:" + str(ttl) + " for device " + str(uuid)
              print "LATENCY: " + str(bw_lat[probe][ttl][1]) + " previous TTL: " + str(bw_lat[probe][ttl-1][1])
            if ceil(log10(bw_lat[probe][ttl][1])) - ceil(log10(bw_lat[probe][ttl-1][1])) >=1: # --> this is the difference of an order of magnitute
                    # if this difference is higher or equal than 1 --> access link detected!
                if options.verbose:
                  print "Access link detected for device " + str(uuid) + ": link " + str(ttl)
                access_link = ttl
                break

            #if bw_lat[probe][ttl][1] >= 3* bw_lat[probe][ttl-1][1] and bw_lat[probe][ttl][1] >= bw_lat[probe][ttl+1][1]:
                #print "Access link detected for probe " + str(probe) + ": link " + str(ttl)
                #access_link[probe] = ttl
                #break
        elif ttl+1 not in bw_lat[probe]:
            print "Access link detection: cannot detect"
            access_link = 0
      except:  
        print "Access link detection: cannot detect"
        access_link = 0
    return int(access_link)

# parse the raw Revelio data from a single device (identified by a uuid) to output a Revelio object
def run_Revelio_charact(data_uuid, uuid):
    # the header of the input file: 
    # boxid,revelio_type,timestamp,local_IP,IGD,STUN_mapped,trace_packetSize,traceroute_result
    if options.verbose:
        print "Revelio ran on this device for " + str(len(list(data_uuid.timestamp.unique()))) + " times."
    nr_runs = len(list(data_uuid.timestamp.unique()))
    
    # get the local IP address
    local = data_uuid.local_IP[0]
    if "br-lan:" in local:
        local_ip = local.split(",")[1].split[":"][0]
    elif "eth0" in local:
        local_ip = local.split(",")[-1].split[":"][0]
    else:
        local_ip = local[0]

    upnp_output = data_uuid.IGD.unique()
    upnp = [] # get all the WAN-facing IP addresses of the device connected to Revelio
    for res in upnp_output:
      if "upnp " in res:
        wan_ip = res.split(" ")[1]
        if wan_ip not in upnp:
          upnp.append(wan_ip)
      elif res == "noIGD":
        if options.verbose:
          print "The device is not connected to an IGD [UPnP is not (always) supported by the CPE!]"

    stun_output = data_uuid.STUN_mapped.unique()
    stun = [] # the set of GRAs we retrieve
    for res in stun_output:
      gra = res.split(" ")[1].split(":")[0] # this is the GRA mapped to the device running the Revelio client
      if gra not in stun:
        stun.append(gra)

    data_trace_GRA = data_uuid[data_uuid.trace_packetSize == 100, ["trace_packetSize","traceroute_result"]
    (trace_GRA_rtt, trace_GRA_IP) = parse_trace(data_trace_GRA)
    if trace_GRA_IP[100].keys():
      trace_gra = length(trace_GRA_IP[100].keys()) # get the number of hops that replied to the traceroute to the GRA
    else:
      trace_gra = 0
    
    # get the location of the access link
    data_traceroute_L3 = data_uuid[data_uuid.trace_packetSize > 100, ( "trace_packetSize","traceroute_result")]
    (trace_L3_rtt, trace_L3_IP) = parse_trace(data_traceroute_L3)
    pathchar = run_pathchar(trace_L3_rtt, uuid) # get location of the access link

    # check if the IP addresses after the access link are shared or private
    if pathchar>0 and IPAddress(local_ip) in private:
      trace_fix = trace_L3_IP[int(pathchar)]['120']
      if trace_fix:
        for ip in trace_fix:
          if IPAddress(ip) in private:
            private_ip = 1 
            shared_ip = 0
          elif IPAddress(ip) in shared:
            private_ip = 0
            shared_ip = 0
      else: # we get no IP address in the traceroutes at TTL = pathchar
        private_ip = shared_ip = 0
    elif IPAddress(local_ip) in shared:
        shared_ip = 1 # the local IP is shared (there is no NAT though in the home -- just the one in the access link) 
        private_ip = 0 
    else:
        shared_ip = private_ip = 0# we don't find anyhting


    # build the Revelio state -- and pass it when building the device
    revelio_state =  Revelio(local_ip, gra, upnp, pathchar, trace_gra, shared_ip, private_ip)
    return revelio_state

# this is the function that checks the results of the Revelio Discovery tests, compares them and gives the result
# we then store this results in the device.nat444 field of the Device object 
def run_Revelio_discovery(revelio_state):
    print "NAT_CPE:" + str(revelio_state.NAT_test()) + "; Trace_GRA:" + str(revelio_state.Traceroute_GRA()) + \
     "; UPnP:" + str(revelio_state.UPnP_GRA()) + "; Shared_IP: " + str(revelio_state.Shared_IP()) + \
      "; Private_after_GRA:" + str(revelio_state.PrivateIPs_in_ISP())
    return 1


#TODO: add an option to read the input raw data from an sqlite file (e.g., leone.db)
#usage = "usage: %prog [options] arg"
parser = OptionParser()
# add another parameter to tell us which is the format of the traceroute
parser.add_option("-i", "--input", dest="input_data",
                  help="Read raw Revelio input in CSV format from FILE. This is a required parameter.", metavar="FILE")
parser.add_option("-o", "--output", dest="out_file",
                  help="Write NAT Revelio results of the discovery phase to FILE", metavar="FILE")
parser.add_option("-f", "--file", dest="parsed_file", 
                  help="Write Revelio parsed results to FILE (after the characterization phase)",  metavar="FILE")
parser.add_option("-v", "--verbose", default=True,
                  help="Output parsing steps info to stdout [default]", action="store_true", dest="verbose")
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=False,
                  help="Don't print status messages to stdout")
#TODO: 
#parser.add_option("-t", "--type", )
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
parsed = open(parsed_file, "w")
output = open(out_file, "w")
   

if options.verbose:
    print "Parsing Revelio raw results from file " + str(input_data) 
data = pd.read_csv(input_data) # we read the data from a CSV file 
                               # the header of the input file: 
                               # boxid,revelio_type,timestamp,local_IP,IGD,STUN_mapped,trace_packetSize,traceroute_result
                               # this comes from the database schema we defined to store the results of the Revelio client
# for each boxid in the database, we need to run the same detection
for uuid in data.boxid.unique():
    revelio_client = Device(uuid)
    #separate the subset of Revelio results coming from a single device 
    if options.verbose:
        print "Parsing Revelio results from device with uuid " + str(uuid)
    data_uuid = data[data.boxid == uuid]
    
    # parse all the raw Revelio data we collect from the device
    revelio_client.revelio = run_Revelio_charact(data_uuid, uuid)
    parsed.write(" ".join(revelio_client.revelio))
    output.write(str(run_Revelio_discovery(revelio_state)))


# if __name__ == '__main__':     #only when run from cmd line
#     main()
