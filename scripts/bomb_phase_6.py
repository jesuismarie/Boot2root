import itertools

values = [253, 725, 301, 997, 212, 432]
nodes = list(range(1, 7))

def is_sorted(sequence):
	vals = [values[i - 1] for i in sequence]
	return all(vals[i] > vals[i + 1] for i in range(len(vals) - 1))

valid_sequences = []

for perm in itertools.permutations(nodes):
	if is_sorted(perm):
		valid_sequences.append(perm)

print("Valid sequences that produce strictly ascending linked list by value:")
for seq in valid_sequences:
	print(seq)
