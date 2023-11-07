S_BOX = [
    [0x9, 0x4, 0xa, 0xb],
    [0xd, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xc, 0xe, 0xf, 0x7]
]

S_BOX_INVERSE = [
    [0xa, 0x5, 0x9, 0xb],
    [0x1, 0x7, 0x8, 0xf],
    [0x6, 0x0, 0x2, 0x3],
    [0xc, 0x4, 0xd, 0xe]
]


def sub_nibbles(state, box):
    """
    Substitutes the nibbles in the state matrix using a given box

    :param state: The state matrix
    :param box: The box to use for substitution. Either S_BOX or S_BOX_INVERSE
    :returns: The state matrix with substituted nibbles
    """

    for i in range(len(state)):
        for j in range(len(state[i])):
            # Grabbing the highest 2 bits of a nibble
            high = (state[i][j] >> 2) & 0b11
            # Grabbing the lowest 2 bits of a nibble
            low = state[i][j] & 0b11
            # Substituing the nibble in the state with one from the box
            state[i][j] = box[high][low]
    # Our state is now substituted
    return state


def shift_rows(state):
    """
    Shifts the rows of the state matrix to the left. The amount of shifting is determined by the row number

    :param state: The state matrix
    :returns: The state matrix with shifted rows
    """

    for i in range(len(state)):
        state[i] = state[i][i:] + state[i][:i]
    return state


def shift_rows_inverse(state):
    """
    Shifts the rows of the state matrix back to its original state.

    :param state: The state matrix
    :returns: The state matrix with shifted rows
    """

    for i in range(len(state)):
        state[i] = state[i][-i:] + state[i][:-i]
    return state


def mix_columns(state):
    """
    Mixes the columns of the state matrix

    :param state: The state matrix
    :returns: The state matrix with mixed columns
    """

    # Define the new state matrix
    new_state = [[0, 0], [0, 0]]

    # Perform the MixColumns operation
    new_state[0][0] = state[0][0] ^ galois_multiplication(4, state[1][0])
    new_state[0][1] = state[0][1] ^ galois_multiplication(4, state[1][1])
    new_state[1][0] = galois_multiplication(4, state[0][0]) ^ state[1][0]
    new_state[1][1] = galois_multiplication(4, state[0][1]) ^ state[1][1]

    return new_state


def mix_columns_inverse(state):
    """
    Mixes the columns of the state matrix back to its original state

    :param state: The state matrix
    :returns: The state matrix with mixed columns
    """
    # Define the new state matrix
    new_state = [[0, 0], [0, 0]]

    # Perform the InvMixColumns operation
    new_state[0][0] = galois_multiplication(
        9, state[0][0]) ^ galois_multiplication(2, state[1][0])
    new_state[0][1] = galois_multiplication(
        9, state[0][1]) ^ galois_multiplication(2, state[1][1])
    new_state[1][0] = galois_multiplication(
        2, state[0][0]) ^ galois_multiplication(9, state[1][0])
    new_state[1][1] = galois_multiplication(
        2, state[0][1]) ^ galois_multiplication(9, state[1][1])

    return new_state


def rotate_word(word):
    """
    Swap the positions of the two nibbles in a word

    :param word: The word to swap nibbles in
    :returns: The word with swapped nibbles
    """

    return ((word & 0x0F) << 4) | ((word & 0xF0) >> 4)


def sub_word(word, box):
    """
    Substitutes the nibbles in a word using a given box

    :param word: The word to substitute nibbles in
    :param box: The box to use for substitution. Either S_BOX or S_BOX_INVERSE
    :returns: The word with substituted nibbles
    """

    # Grabbing the nibbles from the word
    high_nib = (word & 0xF0) >> 4
    low_nib = word & 0x0F

    # Replacing the nibbles with nibbles from the box
    new_nib0 = box[(high_nib & 0b1100) >> 2][high_nib & 0b0011]
    new_nib1 = box[(low_nib & 0b1100) >> 2][low_nib & 0b0011]

    # Returning the new word
    return (new_nib0 << 4) | new_nib1


def add_round_key(state, key):
    """
    XORs the state with the key

    :param state: The state matrix
    :param key: The key to XOR the state with
    :returns: The state matrix with XORed key
    """
    state = state_to_block(state)
    state = state ^ key
    return block_to_state(state)


def key_expansion(cipherkey):
    """
    Expands the cipherkey to 3 round keys

    :param cipherkey: The cipherkey to expand
    :returns: A list of 3 round keys
    """

    keys = []
    rcon = [0x80, 0x30]

    w0 = (cipherkey & 0xFF00) >> 8
    w1 = cipherkey & 0x00FF
    w2 = sub_word(rotate_word(w1), S_BOX) ^ rcon[0] ^ w0
    w3 = w2 ^ w1
    w4 = sub_word(rotate_word(w3), S_BOX) ^ rcon[1] ^ w2
    w5 = w4 ^ w3

    keys.append(w0 << 8 | w1)
    keys.append(w2 << 8 | w3)
    keys.append(w4 << 8 | w5)

    return keys


def encrypt(plaintext, cipherkey):
    """
    Encrypts a plaintext using a cipherkey

    :param plaintext: The plaintext to encrypt
    :pram cipherkey: The cipherkey to use for encryption
    :returns: The ciphertext
    """

    # Expand the cipherkey
    keys = key_expansion(cipherkey)

    # Add the pre-round key
    state = block_to_state(plaintext)
    state = add_round_key(state, keys[0])

    # Perform the first round
    state = sub_nibbles(state, S_BOX)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, keys[1])

    # Perform the second round
    state = sub_nibbles(state, S_BOX)
    state = shift_rows(state)
    state = add_round_key(state, keys[2])

    return state_to_block(state)


def decrypt(ciphertext, cipherkey):
    """
    Decrypts a ciphertext using a cipherkey

    :param ciphertext: The ciphertext to decrypt
    :pram cipherkey: The cipherkey to use for decryption
    :returns: The plaintext
    """

    # Expand the cipherkey
    keys = key_expansion(cipherkey)

    # Add the pre-round key
    state = block_to_state(ciphertext)
    state = add_round_key(state, keys[2])

    # Perform the first round
    state = shift_rows_inverse(state)
    state = sub_nibbles(state, S_BOX_INVERSE)
    state = add_round_key(state, keys[1])
    state = mix_columns_inverse(state)

    # Perform the second round
    state = shift_rows_inverse(state)
    state = sub_nibbles(state, S_BOX_INVERSE)
    state = add_round_key(state, keys[0])

    return state_to_block(state)


def block_to_state(block):
    """
    Converts a 16-bit block to a 2x2 state matrix

    :param block: The block to convert
    :returns: A 2x2 state matrix
    """
    state = [[0, 0], [0, 0]]
    state[0][0] = (block & 0xF000) >> 12
    state[0][1] = (block & 0x0F00) >> 8
    state[1][0] = (block & 0x00F0) >> 4
    state[1][1] = block & 0x000F
    return state


def state_to_block(state):
    """
    Converts a 2x2 state matrix to a 16-bit block

    :param state: The state matrix to convert
    :returns: A 16-bit block
    """
    block = 0
    block |= state[0][0] << 12
    block |= state[0][1] << 8
    block |= state[1][0] << 4
    block |= state[1][1]
    return block


def galois_multiplication(x, y):
    """
    The Galois multiplication function takes two numbers and multiply them according to the rules of the Galois Field

    :param x: The first number
    :param y: The second number
    :returns: The product of the two numbers
    """
    r = 0
    for i in range(4):
        if (y >> i) & 1:
            r ^= x
        hbs = x & 0x8
        x <<= 1
        if hbs:
            x ^= 0x13  # x^4 + x + 1
    return r
