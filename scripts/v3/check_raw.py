import os
raw_files = os.listdir("data/raw")
print("Total files in data/raw:", len(raw_files))
print("Sample files:", raw_files[:20])