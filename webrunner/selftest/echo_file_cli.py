import sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        print("FILE: " + f.read().strip())
except Exception as e:
    print("FILE-ERROR: " + str(e))
