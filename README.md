# NAT revelio
Code to collect network data for the detection of NAT444 solution deployed in the ISP access network.

Revelio is explained in the reasech paper "NAT Revelio: Detecting NAT444 in the ISP" published at PAM 2016.
This repository contains the source code for Revelio.
It needs to be complemented with a storage solution for the raw results. 
Revelio should run at least 50 different times on the same measurement agent in order to be able to run a correct inference on the existence of a NAT444 solution in the ISP.
Then, we need to parse the raw results in order to detect the presence of a NAT444 solution in the ISPs we measure.
