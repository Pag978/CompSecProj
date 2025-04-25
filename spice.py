from Crypto.Random import get_random_bytes

with open("pepper.enc", "wb") as file:
    for i in range(0, 100):
        file.write(get_random_bytes(16))

with open("pickle.enc", "wb") as file:
    for i in range(0, 100):
        file.write(get_random_bytes(16))

with open("pepper.enc", "rb") as file:
    peppers = file.read()

with open("pickle.enc", "rb") as file:
    pickles = file.read()

print(len(peppers))
print(len(pickles))
