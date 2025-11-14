import sys

alertText = '"event_type":"alert"'

with open(sys.argv[1], "r", encoding="utf-8") as f:
    for line in f:
        if alertText in line:
            print(line.strip())