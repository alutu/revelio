# NAT revelio
Code to collect network data for the detection of NAT444 solutions deployed in the ISP access network.

We explain Revelio in the reseach paper titled "NAT Revelio: Detecting NAT444 in the ISP" published at PAM 2016.
This repository contains the source code for the Revelio client.
It needs to be complemented with a storage solution for the raw results. 
Revelio should run at least 50 different times on the same measurement agent in order to be able to perform an accurate inference on the existence of a NAT444 solution in the ISP.
Then, we need to parse the raw results in order to detect the presence of a NAT444 solution in the ISPs we measure.
The Revelio-parser implements the detection tests we include in the Revelio test-suite. 

