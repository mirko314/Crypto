import hashlib

valid="fc34d007cd68dff4a7xxxxxxxxxxxxxx"
salt = "67d46047e06242422adc38bfxxxxxxxx"
for i in range(9999999):
    if i % 100 == 0:
        print(i)
    hash  = hashlib.md5(salt.encode('utf-8') + str(i).encode('utf-8') ).hexdigest()
    if hash == valid:
        print(i)
        break

#Flag 1: 6314
