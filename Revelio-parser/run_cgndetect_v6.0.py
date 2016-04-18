#!/usr/bin/env python
"""
parse the raw data from REVELIO tests in the microworkers:
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
import pandas
from scipy import *
from numpy import *
from matplotlib import *
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit
from scipy.stats import linregress
#import rpy2.rpy_classic as rpy
#from rpy import r  -- gives problems with R3.3, use instead statsmodels
import statsmodels.api as sm
from math import *
from sqlalchemy import create_engine

dslite = IPNetwork("192.0.0.0/29")
sharedIP = IPNetwork("100.64.0.0/10")
private1 = IPNetwork("192.168.0.0/16")
private2 = IPNetwork("10.0.0.0/8")
private3 = IPNetwork("172.16.0.0/12")

#ENGINE_NSB  = create_engine('mysql://alutu:alutu@zompopo.it.uc3m.es/nsb') # sqlalchemy engine for using with pandas
# modify the webapp to process the data from one single measurement agent -- and output if it has CGN or not


class ABLine2D(plt.Line2D):
    """
    Draw a line based on its slope and y-intercept. Keyword arguments are
    passed to the <matplotlib.lines.Line2D> constructor.
    """

    def __init__(self,slope,intercept,**kwargs):

        # get current axes if user has not specified them
        ax = kwargs.pop('axes',plt.gca())

        # if unspecified, get the line color from the axes
        if not (kwargs.has_key('color') or kwargs.has_key('c')):
            kwargs.update({'color':ax._get_lines.color_cycle.next()})

        # init the line, add it to the axes
        super(ABLine2D,self).__init__([None],[None],**kwargs)
        self._slope = slope
        self._intercept = intercept
        ax.add_line(self)

        # cache the renderer, draw the line for the first time
        ax.figure.canvas.draw()
        self._update_lim(None)

        # connect to axis callbacks
        self.axes.callbacks.connect('xlim_changed',self._update_lim)
        self.axes.callbacks.connect('ylim_changed',self._update_lim)

    def _update_lim(self,event):
        """ called whenever axis x/y limits change """
        x = np.array(self.axes.get_xbound())
        y = (self._slope*x)+self._intercept
        self.set_data(x,y)
        self.axes.draw_artist(self)


def uniq(lst): 
    # unique elements with preserving the order of appearence 
        checked = []
        for e in lst:
          ttl = e.split(",")[1]
          hop = e.split(",")[0]
          if hop != "*":
             if (hop, ttl) not in checked:
                checked.append((hop, ttl))
        return checked


"""
get the per-hop RTTs only from the traceroute results
"""
def get_RTTs(trace):
    RTTs = dict()
    hops = [] # if we want to 
    tr = trace.split("|")
    for hop in tr[1:-1]:
       result = hop.split()
       if len(result) == 1:
          return 0
          #break
       if result[1] != "*":
          RTTs[result[0]]  = result[2]
       else:
          RTTs[result[0]]  = "0"
    return RTTs

def get_hopIPs(trace):
    hopIPs = dict()
    hops = [] # if we want to 
    tr = trace.split("|")
    for hop in tr[1:-1]:
       result = hop.split()
       if len(result)==1:
          return 0
          #break
       if result[1] != "*":
          hopIPs[result[0]] = result[1]
       else:
          hopIPs[result[0]] = "*"
    return hopIPs

def rtt_func(x, ibw, lat):
    return x*ibw + lat

def is_private(address):
    #address = IPAddress(ip)
    if address in private1:
       return 1
    elif address in private2:
       return 1
    elif address in private3:
       return 1
    else:
       return -1
def stun_trace(stun, tracert):
    for (hop, ttl) in tracert:
        if (stun == hop):
            return 1 # no CGN
    return -1 # maybe CGN

try:
    print sys.argv
    input_data= sys.argv[1]
    print " Revelio raw data from microworkers: "+ input_data # should be able to get this from the database directly
    # for now, there is a csv file with the results in /Users/andra/Documents/MY_WORK/REVELIO/microwork_results/micro_Revelio.csv
    output = sys.argv[2]
    print " Intermediary output file: " + output # file to store the parsed Revelio results from the microworkers
    res_out = sys.argv[3]
    print " Parsed output file: " + res_out
except:
    print "Usage: run_cgndetect_v6.0.py <input_data file> <intermediary output file> <res-out file>"
    sys.exit(0)


def main():
    out = open(output, 'w+') # output file where we write the "parsed" version of the raw data we get from the probes
    res_file = open(res_out, 'a+') # results file, where we have the actual result of the pathchar algorithm, 
                                   # but NOT the final decision
    data = open(input_data, 'r+')
    # (write and then ) run an additional script to verify the rules we have in the REVELIO flowchart


  ## PANDAS solution
  #   data = pd.read_csv(input_data) # read the Revelio results from the csv file to the pandas data frame
  #   # for each boxid in the database, we need to run the same detection
  #   for uuid in data.boxid.unique():
  #     #separate the subset of Revelio results coming from a single device 
  #     print "Parsing Revelio results from device with uuid " + str(uuid)
  #     dat_uuid = data[data.boxid == uuid]
  #     print "Revelio ran on this device for " + str(len(list(dat_uuid.timestamp.unique()))) + " times"
  #     no_runs = len(list(dat_uuid.timestamp.unique()))
  #     stun = dat_uuid.STUN.unique()  
  #     upnp = dat_uuid.upnp_wan_ip.unique()
    upnp_wan = dict()
    cpe = dict()
    stun = dict()
    hairpin = dict()
    traceroute_rtt = dict() 
    traceroute_ips = dict() 
    failed = []

    for line in data:
        print str(line)
      #boxid,revelio_type,timestamp,local_IP,upnp_wan_ip,STUN,trace_packet_size,traceroute_results
      #try:
        if "boxid" in str(line):
            continue
        info = line.strip().split(",")
        unit = info[0]
        time = info[1]
        IF = info[2] # local interface
        cpe[unit, time] = info[2]

        if (unit, time) not in traceroute_rtt:
          upnp_wan[unit, time] = ""
          stun[unit, time] = ""
          hairpin[unit, time] = "0"
          traceroute_rtt[unit, time] = dict()
          traceroute_ips[unit, time] = dict()
### get upnp address
          if "upnp" in info[3]: #upnp test outputed something or ""
                upnp_wan[unit, time] = info[3].split(" ")[1]
          else: 
                upnp_wan[unit, time] = info[3]
### get stun mapped address
          if "stun" in info[4]:
                stun[unit, time] = info[4].split(" ")[1].split(":")[0]
          else:
                stun[unit, time] = "stun_failed"
### get the RTTs from the traceroute measuremeants
          packet_size = info[5]
          if get_RTTs(info[6]) != 0:
              traceroute_rtt[unit, time][packet_size] = get_RTTs(info[6])
              traceroute_ips[unit, time][packet_size] = get_hopIPs(info[6])
          else:
              print "Traceroute failed: unit " + str(unit) + ", time "  + str(time) + ", packet_size " + str(packet_size) 
        else:
          packet_size = info[5]
          if get_RTTs(info[6]) != 0:
              traceroute_rtt[unit, time][packet_size] = get_RTTs(info[6])
              traceroute_ips[unit, time][packet_size] = get_hopIPs(info[6])
          else:
              print "Traceroute failed: unit " + str(unit) + ", time "  + str(time) + ", packet_size " + str(packet_size)
### output the dataframe we will work with and then read it into a pandas.DataFrame
    out.write('Probe_ID;UPNP;STUN;time;packet_size;TTL;hopIP;RTT\n')
    for (unit, time) in traceroute_rtt:
        for packet_size in traceroute_rtt[unit,time]:
            for ttl in traceroute_rtt[unit, time][packet_size]:
                out.write(str(unit) + ";"  + str(upnp_wan[unit, time]) +  ";" + str(stun[unit, time]) + ";" + str(time) + ";" + str(packet_size) + ";" + str(ttl) + ";" + str(traceroute_ips[unit, time][packet_size][ttl]) + ";" + str(traceroute_rtt[unit, time][packet_size][ttl]) + "\n")
    out.close()
    del upnp_wan, stun, hairpin, traceroute_ips, traceroute_rtt
### read the data as a pandas data frame    
    data = read_csv(output, sep = ";")

### perform statistical analysis for the RTTs from traceroutes [PATHCHAR]
#perform the following per probe and then per TTL:
#1) minimum filtering
#2) curve-fitting
#3) differencing to find the BW and latency values on each link
    SORTTs = dict()
    slope_intercept = dict()
    links = dict()
    hops_to_MA = dict()
    timeout_MA = dict()

    upnp_wan = dict() # the set of WAN-IPs observed over the time of the analysis
    stun = dict() # the set of STUN mapped addresses observed over the time of the analysis
    trace_hop =  []
    #cascade_nat = dict() # number of private IPs which appear consequtively in the traceroute to the fixed address in Level3

    for probe in data['Probe_ID'].unique():
        ### plt.figure(1)
        probe_data = data[data['Probe_ID']==probe] # select the results only from whitebox "probe"
        print "Processing results for Whitebox with unique ID " + str(probe)

        # get some information on the whiteboxes: country and ISP

        upnp_wan[probe] = []
        stun[probe] = []
        hairpin[probe] = []

        # count the number of hops until the STUN-MA for every time the test ran
        hops_to_MA[probe] = set()
        timeout_MA[probe] = set()
        trace_ma = probe_data[probe_data['packet_size'] == 100]
        for t in trace_ma['time'].unique():
            timeout_MA[probe].add(len(trace_ma[trace_ma['time'] == t]['TTL']))
            if "*" in trace_ma[trace_ma['time'] == t]['hopIP'].unique():
                hops_to_MA[probe].add(len(trace_ma[trace_ma['time'] == t]['hopIP'].unique()) - 1)
            else:
                hops_to_MA[probe].add(len(trace_ma[trace_ma['time'] == t]['hopIP'].unique()))
        # output only one value per probe for the following: STUN-MA; UPNP-WAN; HAIRPIN
        upnp_wan[probe] = probe_data['UPNP'].unique()
        stun[probe] = probe_data['STUN'].unique()
        hairpin[probe] = probe_data['Hairpin'].unique()

        # continue with pathchar
        print "TTL vector: " + str(sort(probe_data['TTL'].unique()))
        for ttl in list(sort(probe_data['TTL'].unique())): # separate TTL: process one TTL value at a time
            ttl_probe_data = probe_data[probe_data['TTL']==ttl] # select all the traceroute result for all packet lengths with TTL = ttl
            SORTTs[probe, ttl]= dict()
            print "	\nRunning pathchar for link [TTL]" + str(ttl)
#1)
            for packet_size in ttl_probe_data['packet_size'].unique():
                if packet_size >100 : # exclude the traceroute to the STUN mapped address which is being done with packet_size = 100
                    SORTTs[probe, ttl][packet_size] = ttl_probe_data[ttl_probe_data['packet_size'] == packet_size]['RTT'].quantile(0.2)
				# we use the second percentile .quantile(0.02) instead of the minimum .min()
                    #print "Percentile: " + str(percentile(ttl_probe_data[ttl_probe_data['packet_size'] == packet_size]['RTT'], 2))
                    #print "Quantile: " + str(ttl_probe_data[ttl_probe_data['packet_size'] == packet_size]['RTT'].quantile(0.02))
                else:
                    continue # replace this with counting the number of hops to the STUN mapped address
                             # which is further needed to run the CGN detection
#2)
            # normally, we should have input for 21 different packet sizes, check that we do, otherwise discard since the fitting cannot be done
            print "Number of packet sizes tested: " + str(len(zip([packet_size for packet_size in SORTTs[probe, ttl]], [SORTTs[probe, ttl][packet_size] for packet_size in SORTTs[probe, ttl]])))
            if len(zip([packet_size for packet_size in SORTTs[probe, ttl]], [SORTTs[probe, ttl][packet_size] for packet_size in SORTTs[probe, ttl]])) >= 19 : 

                probe_ttl_df = DataFrame(SORTTs[probe, ttl].items(), columns = ['packet_size', 'min_rtt'])  

                ##print "Data Frame empty: " + str(len(probe_ttl_df.as_matrix()))
                # check that we do have data to work with
                if len(probe_ttl_df.as_matrix()) > 1:
                    linear_model = sm.RLM.from_formula("min_rtt ~ packet_size", data = probe_ttl_df, M=sm.robust.norms.LeastSquares())
                    #linear_model = sm.RLM(probe_ttl_df['min_rtt'], probe_ttl_df['packet_size'], M=sm.robust.norms.LeastSquares)
                    res = linear_model.fit()
                    try:
                        print res.summary()
                    except:
                        print "Error here!!!"

                    slope_intercept[probe, ttl] = [res.params['packet_size'], res.params['Intercept']]
                    if probe not in links:
                        links[probe] = []
                        links[probe].append(ttl)
                    else:
                        links[probe].append(ttl)
                else:
                    print " No input for pathchar"
                ###plt.plot(probe_ttl_df['packet_size'], probe_ttl_df['min_rtt'], 'o', color = 'k')
                ###plt.plot(probe_ttl_df['packet_size'], res.fittedvalues, '-');

                #ABLine2D(res.params['packet_size'], res.params['Intercept'])

            else:
                print " Not enough input to run pathchar: hop did not reply to traceroute"
                slope_intercept[probe, ttl] = [0, 0]

###        plt.xlabel("Packet Size [bytes]")
###        plt.ylabel("RTT [ms]")
###        plt.title("PathChar: Curve Fitting for Probe " + str(probe))
###        plt.show()

#3)
    bw_lat = dict()
    for probe in data['Probe_ID'].unique():

        bw_lat[probe] = dict()
        if slope_intercept[probe, 1][0]>0: ### why for some we don't have values in the slope-intercept?
						### to fix this, we added the probes with not enough data to run pathchar in the slope_intercept dict
						### we conrol for values of 0 
            bw = 8/(1000*slope_intercept[probe, 1][0])
        else:
            bw = 0
        if slope_intercept[probe, 1][1]>0:
            lat = slope_intercept[probe, 1][1]/2
        else:
            lat = 0
        bw_lat[probe][1] = [bw, lat] # values for TTL = 1 --> the first link
        print "Differentiating to obtain BW and LAT estimates for probe " + str(probe)
        print "TTL vector: " + str(sort(data[data['Probe_ID'] == probe]['TTL'].unique()))
        print "	Link 1: BW [Mb] , LAT[ms]: " + str(bw_lat[probe][1])
        if probe in links:
          for ttl in list(links[probe]):
            if ttl+1 < len(list(links[probe])):
#add condition here to take only the non-zero values of the RTT
                if slope_intercept[probe, ttl+1][0] == 0 or slope_intercept[probe, ttl+1][0] == 'nan':
                    slope_intercept[probe, ttl+1][0] = slope_intercept[probe, ttl][0]
                if slope_intercept[probe, ttl+1][0] <= slope_intercept[probe, ttl][0]:
                  try:
                    if (slope_intercept[probe, ttl][0] - slope_intercept[probe, ttl+1][0])/slope_intercept[probe, ttl][0] < 0.5:
                        bw = bw_lat[probe][ttl][0]
                    else:
                        bw = 8/(1000*(slope_intercept[probe, ttl+1][0] - slope_intercept[probe, ttl][0]))
                  except:
                    bw = 0
                else:
                    bw = 8/(1000*(slope_intercept[probe, ttl+1][0] - slope_intercept[probe, ttl][0]))

                if slope_intercept[probe, ttl +1][1] == 0 or slope_intercept[probe, ttl +1][1] == 'nan':
                    slope_intercept[probe, ttl +1][1] = slope_intercept[probe, ttl][1]
                if slope_intercept[probe, ttl +1][1] <= slope_intercept[probe, ttl][1]:
                  try:
                    if (slope_intercept[probe, ttl][1] - slope_intercept[probe, ttl+1][1])/slope_intercept[probe, ttl][1] < 0.5:
                        lat = bw_lat[probe][ttl][1]
                    else:
                        lat = (slope_intercept[probe, ttl +1][1] - slope_intercept[probe, ttl][1])/2
                  except:
                    lat = 0
                else:
                    lat = (slope_intercept[probe, ttl +1][1] - slope_intercept[probe, ttl][1])/2

                bw_lat[probe][ttl+1] = [bw, lat]    
                print "	Link " + str(ttl+1) + ": BW [Mb] , LAT[ms]: " + str(bw_lat[probe][ttl +1])

#4) Detect the access link and the location of the SK Whitebox
    access_link = dict()
    for probe in bw_lat:
        for ttl in bw_lat[probe]:
          try:
            if ttl > 1 and ttl+1 in bw_lat[probe]:
                print "TTL:" + str(ttl) + " for probe " + str(probe)
                print "LATENCY: " + str(bw_lat[probe][ttl][1]) + " previous TTL: " + str(bw_lat[probe][ttl-1][1])
                if ceil(log10(bw_lat[probe][ttl][1])) - ceil(log10(bw_lat[probe][ttl-1][1])) >=1: # --> this is the difference is order of magnitute
												# if this difference is higher or equal than 1 --> access link detected!
                    print "Access link detected for probe " + str(probe) + ": link " + str(ttl)
                    access_link[probe] = ttl
                    break

                #if bw_lat[probe][ttl][1] >= 3* bw_lat[probe][ttl-1][1] and bw_lat[probe][ttl][1] >= bw_lat[probe][ttl+1][1]:
                    #print "Access link detected for probe " + str(probe) + ": link " + str(ttl)
                    #access_link[probe] = ttl
                    #break
            elif ttl+1 not in bw_lat[probe]:
                print "Access link detected for probe " + str(probe) + ": cannot detect"
                access_link[probe] = 0
          except:  
            print "Access link detected for probe " + str(probe) + ": cannot detect"
            access_link[probe] = 0



### output the parsed Revelio output from the whiteboxes, including the output from the pathchar
### output fields: 
### unitID;STUN_MA;UPNP;HAIRPIN;ACCESS-LINK;hops-to-MA;timeout-MA
    for unit in access_link:
        print "Unit number to res_file: " + str(unit)
        res_file.write(str(unit) + ";" + " ".join([str(x) for x in stun[unit]]) + ";"  + " ".join([str(x) for x in upnp_wan[unit]]) + ";" + str(access_link[unit]) + ";" + str(list(hops_to_MA[unit])) + ";" + str(list(timeout_MA[unit])) + "\n")
    res_file.close()


if __name__ == '__main__':     #only when run from cmd line
    main()
