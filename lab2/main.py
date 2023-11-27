from encryption import *


def main():
    inenc = bytearray(b"abcdefghijklmnop")

    outenc = bytearray(16)

    keyenc = bytearray([
        0xE9, 0xDE, 0xE7, 0x2C,
        0x8F, 0x0C, 0x0F, 0xA6,
        0x2D, 0xDB, 0x49, 0xF4,
        0x6F, 0x73, 0x96, 0x47,
        0x06, 0x07, 0x53, 0x16,
        0xED, 0x24, 0x7A, 0x37,
        0x39, 0xCB, 0xA3, 0x83,
        0x03, 0xA9, 0x8B, 0xF6,
    ])

    outdec = bytearray(16)

    ks = bytearray(32)

    mess1 = bytearray(32)

    with open("input.txt", "rb") as file1:
        mess1 = file1.read(32)

    inenc[0:len(mess1)] = mess1

    belt_init(ks, keyenc, 32)
    belt_encrypt(outenc, inenc, ks)

    outencStr = bytes(outenc)

    with open("output.txt", "wb") as file:
        file.write(outencStr)

    print("Encryption:")
    print("Input:", end=" ")
    for byte in inenc:
        print(chr(byte), end=" ")
    print()
    print("Key:", end=" ")
    for byte in ks:
        print(chr(byte), end=" ")
    print()
    print("Output:", end=" ")
    for byte in outenc:
        print(chr(byte), end=" ")

    belt_init(ks, keyenc, 32)
    belt_decrypt(outdec, outenc, ks)

    print("\nDecryption:")
    print("Input:", end=" ")
    for byte in outenc:
        print(chr(byte), end=" ")
    print()
    print("Key:", end=" ")
    for byte in ks:
        print(chr(byte), end=" ")
    print()
    print("Output:", end=" ")
    for byte in outdec:
        print(chr(byte), end=" ")
    print()


if __name__ == "__main__":
    main()
