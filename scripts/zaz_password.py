import hashlib

word = "SLASH"

# Try MD5 hash
md5_hash = hashlib.md5(word.encode()).hexdigest()
print("MD5:", md5_hash)

# Try SHA1 hash
sha1_hash = hashlib.sha1(word.encode()).hexdigest()
print("SHA1:", sha1_hash)

# Try SHA256 hash
sha256_hash = hashlib.sha256(word.encode()).hexdigest()
print("SHA256:", sha256_hash)
