#! /usr/bin/env python3

numbers = []
numbers.append(1)
for i in range(1, 6):
	numbers.append(numbers[i - 1] * (i + 1))
print(numbers)