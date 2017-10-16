#!/usr/bin/python
import re
sf = open("service.txt", "w")
af = open("application.txt", "w")
sf2 = open("service2.txt", "w")
sf2C = open("service2ForCompare.txt", "w")
af2 = open("application2.txt", "w")
with open("nDPI/fortigateApplicationFilterList.txt") as f:
    allFApp = f.readlines()
with open("nDPI/fortigateServiceList.txt") as f:
    allFSer = f.readlines()

with open("protocolList.txt") as f:
    allProtocols = f.readlines()
allProtocolsClear = []
for p in allProtocols:
    result = re.search("--([^\s]+)", p)
    if result:
        cp = result.group(1)
        allProtocolsClear.append(cp)
        doYouFind = False
        for fa in allFApp:
            result2 = re.search("\d+\s+([^\s]*" + cp.lower() + "[^\s]*)", fa.lower(), re.M)
            if result2:
                af.write(cp + "\t" +result2.group(1) + "\n")
                doYouFind = True
                break;
        if not doYouFind:
            sf.write(cp+"\n")

        doYouFind = False
        for fs in allFSer:
            result2 = re.search(cp.lower(), fs.lower(), re.M)
            if result2:
                sf2.write(cp + "\t" + fs)
                doYouFind = True
                break;
        if not doYouFind:
            af2.write(cp+ "\t" + cp + "\n")
    else:
        print "Can't understand this:", p

for fs in allFSer:
    for cp in allProtocolsClear:
        result2 = re.search(cp.lower(), fs.lower(), re.M)
        if result2:
            sf2C.write(fs)
            break;
