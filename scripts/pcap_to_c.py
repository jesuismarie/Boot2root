#!/usr/bin/env python
import os
import re

results = {}

for filename in os.listdir("."):
	if not filename.endswith(".pcap"):
		continue

	try:
		with open(filename, "r") as f:
			content = f.read()
	except:
		continue

	match = re.search(r'//file(\d+)', content)
	if match:
		file_number = int(match.group(1))
		results[file_number] = content

with open("main.c", "w") as f:
	for _, content in sorted(results.items()):
		f.write(content + "\n")