# Classic J2735 Payload Decoder - Single Message
import J2735_201603_2023_02_21
import sys
from time import sleep
from binascii import unhexlify
from collections import defaultdict
    
def fixBSMID(seq, bsm):
    bsmId = seq()['value'][1]['coreData']['id']
    bsmId = bsmId.hex()

    begID = bsm.find("b'") + 2
    endID = bsm.find("'", begID)
    newString = bsm[:begID-2] + str(bsmId) + bsm[endID+1:]

    return newString

def fixTIMID(seq, tim):
    timId = seq()['value'][1]['packetID']
    timId = timId.hex()

    begID = tim.find("b'") + 2
    endID = tim.find("'", begID)
    newString = tim[:begID-2] + str(timId) + tim[endID+1:]

    return newString
    
def convID(id, length):
    id = id.hex()
    i = 0
    if (length == 8):
        while(i<21):
            id = id[:i+2] + " " + id[i+2:]
            i += 3
    else:
        while(i<45):
            id = id[:i+2] + " " + id[i+2:]
            i += 3

    id = list(id.split(" "))

    for x in range(len(id)):
        inted = int(id[x], 16)
        id[x] = inted

    return id

def fix(hexPayload, seq, strId):
    if (hexPayload[:4] == "0014"):
        fixedBSM = fixBSMID(seq, strId)

        return fixedBSM

    elif (hexPayload[:4] == "001f"):
        fixedTIM = fixTIMID(seq, strId)

        return fixedTIM

    elif (hexPayload[:4] == "00f4"):
        reqid = seq()['value'][1]['body'][1]['reqid']
        newReqId = str(convID(reqid, 8))

        begID = strId.find("b'") + 2
        endID = strId.find("'", begID)
        newString = strId[:begID-2] + newReqId + strId[endID+1:]

        return newString

    elif (hexPayload[:4] == "00f5"):
        reqid = seq()['value'][1]['body'][1]['reqid']
        tcmId = seq()['value'][1]['body'][1]['id']
        tcId = seq()['value'][1]['body'][1]['package']['tcids'][0]
        newReqId = str(convID(reqid, 8))
        newTcmId = str(convID(tcmId, 16))
        newtcId = str(convID(tcId, 16))
        newIds = [newReqId, newTcmId, newtcId]

        for b in range(len(newIds)):
            begID = strId.find("b'") + 2
            endID = strId.find("'", begID)
            strId = strId[:begID-2] + newIds[b] + strId[endID+1:]

        return strId
    
    else:
        print("ID fix not included in filters yet. Unfixed message:\n")
        print(strId, "\n")


def main():

    decode = J2735_201603_2023_02_21.DSRC.MessageFrame
    f = open('pcap.txt', 'r')
    Lines = f.readlines()
    f.close()

    fileName = 'decoded_' + sys.argv[1].replace('pcap', 'txt')
    w = open(fileName, 'w')

    msgIds=['0012', '0013', '0014', '001f', '0020'] # this can be updated to include other PSIDs
    decoded_msgId_count = defaultdict(int)  # Dictionary to track decoded msgId and their counts

    print('Processing...\n')
    sleep(0.5)
    for line in Lines:
        for id1 in msgIds:
            idx = line.find(id1)
            if  (idx != -1 and idx < 50 and idx > 24):
                print(line[idx:])
                w.write(line[idx:])
                data = line[idx:].strip('\n')
                # send Hex string to port
                decode.from_uper(unhexlify(data))
                decodedStr = str(decode())

                # if no issues with decoding, print
                if "b'" not in decodedStr: 
                    print(decodedStr, '\n')
                    w.write(decodedStr)
                    w.write('\n')
                    decoded_msgId_count[id1] += 1  # Increment count for successfully decoded msgId

                # decoding issues found, fix and update message
                else: 
                    print('\n', fix(data, decode, decodedStr), '\n')
                    w.write(fix(data, decode, decodedStr))
                    w.write('\n')
                    decoded_msgId_count[id1] += 1  # Increment count for successfully decoded msgId

    # Write the decoded message IDs and their counts to the output file
    w.write('\nDecoded Message ID Counts:\n')
    print('\nDecoded Message ID Counts:')
    for msgId, count in decoded_msgId_count.items():
        w.write(f'{msgId}: {count} times\n')
        print(f'{msgId}: {count} times')

    w.close()
    print('Decoding Complete. Check', fileName, '\n')
    sys.exit(0)  # Automatically terminate the program after completion

if __name__=="__main__":
    main()
