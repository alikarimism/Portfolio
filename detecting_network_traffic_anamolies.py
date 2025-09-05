from scapy.all import *
from pandas import Series
from scapy.layers.http import *
import traceback

threshold = 10
def calculatelikelihood(feature):
    counts=Series(feature[0:-1]).value_counts().to_dict()
    if feature[-1] in counts:
        return float(counts[feature[-1]])/float(len(feature))
    else:
        return 0.1/len(feature)


def extractHTTPRequest(p , features):
    features["UserAgent"].append(p[HTTPRequest].User_Agent)
    features["Cookie"].append(p[HTTPRequest].Cookie)
    features["Host"].append(p[HTTPRequest].Host)
    features["Referer"].append(p[HTTPRequest].Referer)
    features["Path"].append(p[HTTPRequest].Path)
    features["Method"].append(p[HTTPRequest].Method)

    if len(features[UserAgent]) > threshold:
        probability = 1.0
        for feature in features:
            probability *= calculatelikelihood(features[feature])    
    else:
        probability = 1.0
    return [features,probability]

def extractHTTPResponse(p , features):
    features["StatuseCode"].append(p[HTTPResponse].Statuse_Code)
    features["Server"].append(p[HTTPResponse].Server)
    if len(features["server"]) > threshold :
        probability = 1.0
        for feature in features :
            probability *= calculatelikelihood(features[feature])
    else:
        probability = 1.0
    return [features , probability]



def extract_tcp(p , client, features):
    if client:
        port = p[TCP].dport
    else:
        port = p[TCP].sport
    features["port"].append(port)
    features["flags"].append(p[TCP].flags)
    if len(features["flags"]) > threshold :
        probability = 1
        for feature in features :
            probability *= calculatelikelihood(features[feature])
    else:
        probability = 1
    return [features , probability]


def extractip(p , client , features):
    if client:
        cIP = p[IP].src
        sIP = p[IP].dst
    else:
        sIP = p[IP].src
        cIP = p[IP].dst
    features["sIP"].append(sIP)
    features["cIP"].append(cIP)
    features["conn"].append("%s --> %s" %(cIP , sIP))
    if len(features["conn"]) > threshold :
        probability = 1
        for feature in features :
            probability *= calculatelikelihood(features[feature])
    else:
        probability = 1
    return [features , probability]

features={}
num = 0

def processpacket(p):
    try:
        global features , num
        probs= 1.0
        num += 1
        if p.haslayer(IP):
            if p.haslayer(TCP):
                client = p[TCP].sport >= 49152
                features["TCP"] , x =extract_tcp(p , client , features["TCP"])
            elif p.haslayer(UDP):
                client = p[UDP].sport >= 49152
                features["udp"] , x =extract_udp(p , client , features["UDP"])
            else:
                return
            features ["IP"] , x =extractip(p,client,features["IP"])

            probs *= x

            if p.haslayer(HTTPRequest):
                features[HTTPRequest] , x = extractHTTPRequest(p , features[HTTPRequest])
            if p.haslayer(HTTPResponse):
                features[HTTPResponse] , x = extractHTTPResponse(p , features[HTTPResponse])
                probs *= x      

        if probs != 1.0 :
            print("packet %d has probability of %f" %(num,probs))       
    except Exception as e:
        print("[ERROR] in processpacket:", e)
        traceback.print_exc()

protos={
    "IP":["cIP" , "sIP" , "conn"],
    "TCP":["port", "flags"],
    "UDP":["port"],
    "HTTPRequest" : ["Method" , "Path" ,"Cookie" , "Host" ,"UserAgent" ,"Referer"],
    "HTTPResponse" :["StatuseCode" ,"Server"]
}

def initdict():
    global features
    for p in protos:
        features[p]= {}
        for x in protos[p]:
            features[p][x] = []

initdict()

sniff(prn=processpacket , store=False)
