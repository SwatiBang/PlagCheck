import argparse
import fParser

def deep_check(d1, d2):
    diff = 0
    # Find non-dicts that are only in compto
    for item in d1.items():
        if d2.has_key(item[0]):
            d2[item[0]] = d2[item[0]] - 1
            if d2[item[0]] == 0:
                del d2[item[0]]
        else:
            diff = diff + 1

    return diff;


parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description='File comparer compares 2 files and prints similarity between files.',
                                         prefix_chars='-+/',
                                                                          )

parser.add_argument('-f1', action='store', dest='filename1',
                            help='name of first file to compare')
parser.add_argument('-f2', action='store', dest='filename2',
                            help='name of second file to compare')
results = parser.parse_args()

d1 = fParser.parseFile(results.filename1)
d2 = fParser.parseFile(results.filename2)

f1 = results.filename1
f2 = results.filename2

len2 = len(d2)
diff1 = deep_check(d1,d2)
diff2 =  len(d2)

perD1 = (diff1 * 100)/len(d1)
perD2 = (diff2 * 100)/len2

print f1 + " is " + str(100 - perD1) + " percentage similar to " + f2
print f2 + " is " + str(100 - perD2) + " percentage similar to " + f1
