import cbor2


with open("payload1.cbor", "wb") as f:
    data = [1, 2]
    cbor_data = cbor2.dumps(data)
    f.write(cbor_data)
    print("This is the cbor data with 1", cbor_data)

with open("payload1long.cbor", "wb") as f:
    data = [1, 2, 3]
    cbor_data = cbor2.dumps(data)
    f.write(cbor_data)

with open("payload2.cbor", "wb") as f:
    data = [2, 2]
    cbor_data = cbor2.dumps(data)
    f.write(cbor_data)
    print("This is the cbor data with 2", cbor_data)
