#! /usr/bin/env python3
import sys

def func4(nb):
	if nb <= 1:
		return 1
	return func4(nb - 1) + func4(nb - 2)

for i in range(100):
	nb = func4(i)
	if nb == 55:
		print("Found :", i)
		sys.exit(0)