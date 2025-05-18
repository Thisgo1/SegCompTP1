# Permutações
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

# S-boxes
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


# Funções auxiliares
def permuta(bits, padrao):
    return [bits[i - 1] for i in padrao]


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def sbox_lookup(bits, sbox):
    row = (bits[0] << 1) + bits[3]
    col = (bits[1] << 1) + bits[2]
    val = sbox[row][col]
    return [(val >> 1) & 1, val & 1]


def fk(bits, key):
    left, right = bits[:4], bits[4:]
    expand = permuta(right, EP)
    xor_result = [a ^ b for a, b in zip(expand, key)]
    s0_result = sbox_lookup(xor_result[:4], S0)
    s1_result = sbox_lookup(xor_result[4:], S1)
    combined = permuta(s0_result + s1_result, P4)
    left_result = [a ^ b for a, b in zip(left, combined)]
    return left_result + right


def generate_keys(key):
    key = permuta(key, P10)
    left, right = key[:5], key[5:]
    left1 = left_shift(left, 1)
    right1 = left_shift(right, 1)
    k1 = permuta(left1 + right1, P8)
    left2 = left_shift(left1, 2)
    right2 = left_shift(right1, 2)
    k2 = permuta(left2 + right2, P8)
    return k1, k2


def encrypt(plaintext, k1, k2):
    bits = permuta(plaintext, IP)
    temp = fk(bits, k1)
    swap = temp[4:] + temp[:4]
    temp = fk(swap, k2)
    return permuta(temp, IP_INV)


def decrypt(ciphertext, k1, k2):
    bits = permuta(ciphertext, IP)
    temp = fk(bits, k2)
    swap = temp[4:] + temp[:4]
    temp = fk(swap, k1)
    return permuta(temp, IP_INV)


def str_to_bits(s):
    return [int(c) for c in s]


def bits_to_str(bits):
    return "".join(str(b) for b in bits)


def bits_to_bytes(bits):
    byte = 0
    for bit in bits:
        byte = (byte << 1) | bit
    return byte


def bytes_to_bits(byte):
    return [(byte >> i) & 1 for i in range(7, -1, -1)]


# Modos de operação
def ecb_encrypt(message, key):
    k1, k2 = generate_keys(key)
    blocks = [message[i : i + 8] for i in range(0, len(message), 8)]
    ciphertext = []
    for block in blocks:
        ciphertext += encrypt(block, k1, k2)
    return ciphertext


def ecb_decrypt(ciphertext, key):
    k1, k2 = generate_keys(key)
    blocks = [ciphertext[i : i + 8] for i in range(0, len(ciphertext), 8)]
    plaintext = []
    for block in blocks:
        plaintext += decrypt(block, k1, k2)
    return plaintext


def cbc_encrypt(message, key, iv):
    k1, k2 = generate_keys(key)
    blocks = [message[i : i + 8] for i in range(0, len(message), 8)]
    ciphertext = []
    previous = iv.copy()
    for block in blocks:
        xor_block = [a ^ b for a, b in zip(block, previous)]
        encrypted = encrypt(xor_block, k1, k2)
        ciphertext += encrypted
        previous = encrypted.copy()
    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    k1, k2 = generate_keys(key)
    blocks = [ciphertext[i : i + 8] for i in range(0, len(ciphertext), 8)]
    plaintext = []
    previous = iv.copy()
    for block in blocks:
        decrypted = decrypt(block, k1, k2)
        xor_block = [a ^ b for a, b in zip(decrypted, previous)]
        plaintext += xor_block
        previous = block.copy()
    return plaintext


# Interface
def main():
    # Parte I - Criptografia básica
    print("Parte I - Criptografia básica S-DES")
    key_input = input("Chave de 10 bits (ex: 1010000010): ").strip()
    if len(key_input) != 10 or not set(key_input).issubset({"0", "1"}):
        print("Chave inválida.")
        return

    key = str_to_bits(key_input)
    k1, k2 = generate_keys(key)

    mode = input("Digite 'e' para encriptar ou 'd' para decriptar: ").strip().lower()
    data_input = input("Bloco de dados de 8 bits (ex: 11010111): ").strip()
    if len(data_input) != 8 or not set(data_input).issubset({"0", "1"}):
        print("Dados inválidos.")
        return

    data = str_to_bits(data_input)

    if mode == "e":
        result = encrypt(data, k1, k2)
        print("Texto cifrado:", bits_to_str(result))
    elif mode == "d":
        result = decrypt(data, k1, k2)
        print("Texto decifrado:", bits_to_str(result))
    else:
        print("Modo inválido.")

    # Parte II - Modos de operação
    print("\nParte II - Modos de operação")
    message_input = input(
        "Mensagem em bits (ex: 11010111011011001011101011110000): "
    ).replace(" ", "")
    if not set(message_input).issubset({"0", "1"}) or len(message_input) % 8 != 0:
        print("Mensagem inválida. Deve ser múltiplo de 8 bits.")
        return

    message = str_to_bits(message_input)

    mode_op = input("Digite 'ecb' para ECB ou 'cbc' para CBC: ").strip().lower()

    if mode_op == "ecb":
        ciphertext = ecb_encrypt(message, key)
        print("ECB Cifrado:", bits_to_str(ciphertext))
        plaintext = ecb_decrypt(ciphertext, key)
        print("ECB Decifrado:", bits_to_str(plaintext))
    elif mode_op == "cbc":
        iv_input = input(
            "Vetor de inicialização (IV) de 8 bits (ex: 01010101): "
        ).strip()
        if len(iv_input) != 8 or not set(iv_input).issubset({"0", "1"}):
            print("IV inválido.")
            return
        iv = str_to_bits(iv_input)
        ciphertext = cbc_encrypt(message, key, iv)
        print("CBC Cifrado:", bits_to_str(ciphertext))
        plaintext = cbc_decrypt(ciphertext, key, iv)
        print("CBC Decifrado:", bits_to_str(plaintext))
    else:
        print("Modo de operação inválido.")


if __name__ == "__main__":
    main()
