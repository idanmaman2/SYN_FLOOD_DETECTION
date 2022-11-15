from scapy.all import *
packets = rdpcap("/home/idang/Downloads/synfloods/SynFloodSample.pcap")
packets.sort(key=lambda x: float(x.time))  # all the time of all the packets
origin_time = [float(pct.time) for pct in packets]
unique_time = list(set(origin_time))  # only unique times - each time is only one time is in this array
unique_time.sort()
lastIndex = 0
Indexes = []
sub_arrays = []  # array of arrays that each array contains packets from one time
Hackers = []  # Ips and Risk_Level of potential hackers
Hackers_Final = set()
# Test 1
# At start i looked on wire shark and all the times looked really suspicious to me so I ran a script to investigate them
# and I discovered that there only 5 different times so I wrote a script that
# look for all the Packets that sent in the same time and more then 1 syn packet (2+)
# sent from the same source in that time
# Create sub_arrays with his 5 arrays
for i in range(len(unique_time)):
	Indexes.append(origin_time.index(unique_time[i]))
for i in range(len(unique_time)):
	if i == len(unique_time)-1:
		sub_arrays.append(packets[Indexes[i]:Indexes[len(unique_time)-1]])
	else:
		sub_arrays.append(packets[Indexes[i]:Indexes[i+1]])
IPS = [[j[IP].src for j in i] for i in sub_arrays]  # all the source ips of all the Users organized by arrays of times
# - for good looking code
for i in range(len(IPS)):
	for j in range(len(IPS[i])):
		if IPS[i].count(IPS[i][j]) > 1 and sub_arrays[i][j][TCP].flags == "S":
			if (IPS[i][j], IPS[i].count(IPS[i][j])) not in Hackers:
				Hackers.append((IPS[i][j], IPS[i].count(IPS[i][j])))
				Hackers_Final.add(IPS[i][j])  # counts in Hacker  the number of
				# syn packets that this user sent in that time
# (ip,RISK_LEVEL)
Hackers_for_sure = {}
# Sorting by Risk Level and if there is Two ips that reached to the same
# risk level in two different times it creates a new Risk
# Level for them - Never happens (but the code is nice so I left it)
for i in Hackers:
	if i[1] in Hackers_for_sure:
		if i[0] not in Hackers_for_sure[i[1]]:
			Hackers_for_sure[i[1]].append(i[0])
		else:
			Hackers_for_sure[i[1]].pop(Hackers_for_sure[i[1]].index(i[0]))
			Rename = str(i[1]) + '*' + str(Hackers_for_sure.count(i))
			if stry in Hackers_for_sure:
				if i[0] not in Hackers_for_sure[stry]:
					Hackers_for_sure.append(i[0])
			else:
				Hackers_for_sure.update({stry: [i[0]]})
	else:
		Hackers_for_sure.update({i[1]: [i[0]]})
# print
for key in Hackers_for_sure:
	print("\tRisk Level :", key)
	print("\tIps: ", Hackers_for_sure[key])
	print("\tnum: ", len(Hackers_for_sure[key]), " \n")
Hackers = [i[0] for i in Hackers]
Hackers_for_sure = []
for i in Hackers:
	if Hackers.count(i) > 1 and i not in Hackers_for_sure:
		Hackers_for_sure.append(i)
Hackers_for_sure = [(i, Hackers.count(i)) for i in Hackers_for_sure]
print("Hackers that tried to attack a few times:")
print("\t", Hackers_for_sure)
print("\tnum:", end=" ")
print(len(Hackers_for_sure))
# Risk_Level - num of the packet he sent in one time .
# But i found some duplicates (sent a few packets in one time in a few times) ip’s so i wrote
# Test 2
# but I thought that the hacker can be smart and send packets one after another in little time spaces ,
# we can see that the max time between two times of the pcap file is 0.00400001..
# we can also say is equivalent to 0.0041 for our case  so i wrote some more code that research that
# as we can see it is obvious that ip’s that has been shown by test1 will be shown by test2
# test2 is easier than test1 .

print("Hackers find by low delta time between packets(0.0041 -45ips) can be changed to (0.004 -33 ips)")
Hackers_List = [(pct[IP].src, float(pct.time), pct[TCP].flags) for pct in packets]
Hackers = {}  # write each ip that sent packet with key = ip val = [last packet time , how many times \ Risk Level ]
# and if we get new packet the time of the last packets changes and if the delta is smaller than 0.0041
# we upload risk level by one
for i in Hackers_List:
	if i[0] in Hackers:
		if (abs(i[1]-Hackers[i[0]][0]) < 0.0041) and i[2] == "S":
			Hackers[i[0]][1] = Hackers[i[0]][1] + 1
		Hackers[i[0]][0] = i[1]
	if i[0] not in Hackers:
		Hackers.update({i[0]: [i[1], 0]})
# sort by Risk Level with Dict key = Risk Level val = [ips]
Hackers_tmp = []
Hacker_tmp2 = set()
for i in Hackers:
	if Hackers[i][1] > 0:
		Hackers_tmp.append((i, Hackers[i][1]+1))
		Hacker_tmp2.add(i)
Hackers_Final.intersection_update(Hacker_tmp2)
Hackers = Hackers_tmp
Hackers.sort(key=lambda x: x[1])
Hackers_for_sure = {}
for i in Hackers:
	if i[1] in Hackers_for_sure:
		Hackers_for_sure[i[1]].append(i[0])
	else:
		Hackers_for_sure.update({i[1]: [i[0]]})
# print
for i in Hackers_for_sure:
	print("\tRisk Level: ", i)
	# Risk Level : how many times he sent packets with short delta time(0.0041) between the packets .
	print("\tips: ", Hackers_for_sure[i])
	print("\tnum: ", len(Hackers_for_sure[i]), "\n")
print("\npassed 2/2 tests :")
print(Hackers_Final, "\n")
# Test 3
# and after that I thought about the basic Syn floods test :
# check who sent syn and got syn+ack and didn't replay ack cause he sent the syn from fake ip
# so i wrote some more code:
Hackers2 = set()  # set of all the ips that syn+ack sent to them
for pct in packets:
	if pct[TCP].flags == "SA":
		Hackers2.add(pct[IP].dst)
	if pct[TCP].flags == "A":
		Hackers2.discard(pct[IP].src)  # if he sent ack we remove him from the suspect list
print("Hackers that used fake IP and didn't response to syn+ack")
print(Hackers2)  # print
# Total
# Sum up  all the ips that has been shown in all the tests - Hackers - 100% 
Hackers_Final.intersection_update(Hackers2)
print("Passed all 3/3 tests: ")
if Hackers_Final == set():
	print(None)
else:
	print(Hackers_Final)
