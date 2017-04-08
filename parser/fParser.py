def parseFile(filename):
    with open(filename,'r') as f:
        d = {}
        q1 = []
        first=""
        second=""
        third=""

        count = 0
        for line in f:
            for word in line.split():
                word = word.strip('.')
                word = word.strip()
                word = word.strip(',')
                if len(word) > 2:
                    count = count + 1
                    if count > 3:
                       q1.pop()

                    q1.insert(0,word)
                    triplet = ""

                    for t in q1:
                        triplet = triplet + ":" + t

                    if d.has_key(triplet):
                        d[triplet] = d[triplet] + 1
                    else:
                        d[triplet] = 1
    return d;


