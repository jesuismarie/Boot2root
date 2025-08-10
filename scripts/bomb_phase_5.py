#! /usr/bin/env python3

table = "isrveawhobpnutfg"
target = "giants"

# get target indices
target_indices = [table.index(c) for c in target]

# build all possible inputs
from itertools import product

possible_inputs = []
for idx in target_indices:
	chars = [chr(i) for i in range(32, 127) if (i & 0x0F) == idx]
	possible_inputs.append(chars)

# check if opekmq and opukmq are in the set
found = []
for combo in product(*possible_inputs):
	s = ''.join(combo)
	if s in ["opekmq", "opukmq"]:
		found.append(s)

print("Found:", found)


