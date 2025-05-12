from typing import Sequence
from .transaction import PartialTxInput, TxOutpoint
from .segwit_addr import bech32_decode, convertbits, DecodedBech32
import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash
from .bitcoin import taproot_output_script, script_to_address, address_to_script, taproot_tweak_pubkey, construct_script

# TODO: Check in bitcoin.py "DummyAddress" and what its used for. Maybe we find something useful for input selection with dummy addresses
# TODO: Dive into plugins. e.g. wallet.make_unsigned_transaction runs a hook in the end. Maybe this would be a place to calculate the output addresses.

def create_outputs():
    """
    Reference Implementation for this function takes:
        - input_priv_keys: priv_keys that were used for all inputs in this tx that are shared-secret-derivation eligible
        - outpoints: outpoints that are referenced by the inputs
        - recipients: a list of all recipients (silent payments addresses)
        - hrp: human-readable-part (basically defines the net)

        A challenging thing is the order of how things happen here. We found out, that if a wallet is of a specific script type
        (e.g. p2wpkh) we can basically skip the part of filtering ineligible inputs when calculating the shared secret, because
        there will never be a utxo with a script type other than the one the wallet defines (defined by seed phrase version).

        We have to find out, what code electrum already has written and how we can make use of it. For example, electrum has a
        coinchooser script, that chooses the inputs for a transaction. The most convenient scenario would be, that we could give
        the coinchooser a set of elible utxo (they are anyway in standard single-script wallets) (and output amount) and then, based on the coins
        chosen do all the calculations to derive the shared secret and construct the outputs. There will be edge cases, since
        in electrum you can select multiple recipients, therefore mixed outputs for one or more "normal" recipients and one or more
        silent payment recipients.



    """
    pass



def handle_silent_payment(wallet):
    test_addr = "tsp1qqw4j6kx8hd0leapusqcyx3gdq34az84gsjhxh82ka9y3yy09j4tvwq44ku34neq5w34xkfzplsdhs2aqsrkdxcvkcsjpm0290vfarx7dkg0nlyl8"
    test_addr1 = "tsp1qq0aut0j4rpngmjf55a6nr98h0kvlc2s83jwv8h9rmaqpgjqvc67wyqefkstjcfchzd9hpy84qara7dwu6jfpx2p9amjwg4j4hv3hsla8nvqa4ap0"
    to_silvio_addr = "tsp1qq0aut0j4rpngmjf55a6nr98h0kvlc2s83jwv8h9rmaqpgjqvc67wyqefkstjcfchzd9hpy84qara7dwu6jfpx2p9amjwg4j4hv3hsla8nvqa4ap0"
    """
    test_addr_gen_spaddr = "tb1p2kmyh6l9lk7wjmzq78dgxu4y5ee4r620e28s7xpxk5lzye2cxg8qtvg9sz"

    b_scan_raw = "85d1aac5c0c0aeab7d2cb6ec4e22b2c1c64ec72f26649995730530fb9c3754bd"
    b_spend_raw = "498e3e2a4aa1088194711019636f6cb2bdb60e8fa1479a480c73a7b13a0b9f70"
    B_scan_raw = "03ab2d58c7bb5ffcf43c803043450d046bd11ea884ae6b9d56e9491211e59556c7"
    B_spend_raw = "02b5b72359e414746a6b2441fc1b782ba080ecd36196c4241dbd457b13d19bcdb2"

    B_scan, B_spend = decode_silent_payment_addr(test_addr)

    assert B_scan.get_public_key_hex() == ecc.ECPrivkey(bytes.fromhex(b_scan_raw)).get_public_key_hex(), "b_scan mismatch B_scan"
    assert B_spend.get_public_key_hex() == ecc.ECPrivkey(bytes.fromhex(b_spend_raw)).get_public_key_hex(), "b_spend mismatch B_spend"


    print(f"B_scan from js  : {B_scan_raw}")
    print(f"B_scan from me  : {B_scan.get_public_key_hex()}")
    print(f"B_spend from js : {B_spend_raw}")
    print(f"B_spend from me : {B_spend.get_public_key_hex()}")

    pub = address_to_script(test_addr_gen_spaddr).hex()
    print(f"pub output: {pub}")
    print(f"{len(pub)=}")

    privkey1 = ecc.ECPrivkey(wallet.keystore.get_private_key(wallet.get_address_index("tb1q8pmsrmhk08wdphkgv7mvt5v3sxk362ghcyj3jk"), password=None)[0])
    privkey2 = ecc.ECPrivkey(wallet.keystore.get_private_key(wallet.get_address_index("tb1qkww6jvflqkztud5uwjcc3p64q4yfz9u77vta6v"), password=None)[0])


    print(f"priv1: {privkey1.secret_scalar}") # 17503924577110619944639076770624100621389804013763496048536240148289303468714
    print(f"priv2: {privkey2.secret_scalar}") # 10863803861633417286734423129731833668770918257673422093103656033065915719332

    print(f"pub1: {privkey1.get_public_key_hex()}") # 03f63ef2180868a3c7deb59550f4eb00efe45bea76d1e5738ab95ed4a9bd57f489
    print(f"pub2: {privkey2.get_public_key_hex()}") # 03ffb7bebfcda30f992ea82f2ffda4507d6336b04ae418f3c72e84943d14d399d4

    a_sum = privkey1.secret_scalar + privkey2.secret_scalar
    A_sum = privkey1 + privkey2

    print(f"privSum without modulo  : {a_sum}")
    print(f"privSum with modulo     : {a_sum % ecc.CURVE_ORDER}")
    print(f"pubSum direct addition  : {A_sum.get_public_key_hex()}")
    print(f"pub generated from a_sum: {ecc.ECPrivkey(int.to_bytes(a_sum % ecc.CURVE_ORDER, length=32, byteorder='big', signed=False)).get_public_key_hex()}")
    print(f"from ref                : 02726d16f99a6efe1f9a7ab6c7d1143ad1b52957f84fd5d16414982c7b293c3871")

    # TODO: CHECK INPUT HASH WITH OUTPOINTS AND COMPARE
    outpoint1_bytes = TxOutpoint(bytes.fromhex("5d2c8f41cce6c1ba012714856887697a6851884f7fafcd9fd582a0123268354c"), 0).serialize_to_network()
    outpoint2_bytes = TxOutpoint(bytes.fromhex("ce58480c284d08739a772b083b770ce2a4d9b04c4391370670937fcfdd593495"), 0).serialize_to_network()

    lowest_outpoint = sorted([outpoint1_bytes, outpoint2_bytes])[0]

    input_hash = bip340_tagged_hash(b"BIP0352/Inputs", lowest_outpoint + A_sum.get_public_key_bytes())
    print(f"input hash              : {input_hash.hex()}")

    ecdh_shared_secret_a_sum = ecc.string_to_number(input_hash) * (a_sum % ecc.CURVE_ORDER) * B_scan
    ecdh_shared_secret_A_sum = ecc.string_to_number(input_hash) * A_sum * ecc.ECPrivkey(bytes.fromhex(b_scan_raw)).secret_scalar

    print(f"{ecdh_shared_secret_a_sum=}")
    print(f"{ecdh_shared_secret_A_sum=}")
    #   90c1d5f7709f3dafba0c74c1d4002eae13d03296d6a179107e39a4fde9b3b184
    # 0290c1d5f7709f3dafba0c74c1d4002eae13d03296d6a179107e39a4fde9b3b184

    k = 0
    t_k = bip340_tagged_hash(b"BIP0352/SharedSecret", ecdh_shared_secret_A_sum.get_public_key_bytes() + k.to_bytes(4, "big"))
    print(f"{t_k.hex()=}")

    # 53d562e1a6dc49c7af0eac829b9c395ebbfe1cd75bf993439f97535f0f7e5c41
    # 53d562e1a6dc49c7af0eac829b9c395ebbfe1cd75bf993439f97535f0f7e5c41

    output_pubkey = B_spend + ((ecc.string_to_number(t_k) % ecc.CURVE_ORDER) * ecc.GENERATOR)
    print(f"{output_pubkey=}")

    spk = (b'\x51\x20' + output_pubkey.get_public_key_bytes()[1:]).hex()
    print(f"{spk=}")
    tweak_output_pubkey = taproot_tweak_pubkey(output_pubkey.get_public_key_bytes()[1:], bytes())
    print(f"{tweak_output_pubkey[1].hex()=}")



    return
    """

    # Select inputs: For now, we select inputs manually for testing purposes, but later, we should:
    #   - filter out invalid inputs
    #   - give valid input to something like coinchooser with a target amount, and let him choose a good combination of inputs

    # As of now, I have 2 coins in my wallet with amount 1000 and 859 so a total balance of 1859 sats
    # For testing purposes, I will later send coins to the silent payment address above with amount: 1000 < amount < 1859.
    # like this, I can construct now the output address, because I know for sure, that both coins will be picked

    # get all utxo in wallet
    coins: Sequence[PartialTxInput] = wallet.get_spendable_coins(confirmed_only=False)
    # 500000 sats ->
    # 25315  sats ->
    # choose output value to ensure both outputs are picket efficiently: 0.26
    coins = [c for c in coins if c.address != "tb1qq97yh8pwyem26lkqk9zr6syfa5vftnqa4zkjzt"]
    # add more info, since some fields are not filled otherwise
    for c in coins:
        wallet.add_input_info(c)
        print(c.to_json())

    # we need the prevouts (outpoints) of the inputs
    # this is done to prevent address reuse, since every txid is unique
    prevouts_ser = [c.prevout.serialize_to_network() for c in coins]
    # we only need the lowest prevout
    lowest_prevout = sorted(prevouts_ser)[0]
    #print(f"1: {hex(int.from_bytes(prevouts_ser[0]))}\n2: {hex(int.from_bytes(prevouts_ser[1]))}\nlowest: {hex(int.from_bytes(lowest_prevout))}")

    # We also need all input private keys of the valid inputs for shared secret derivation (all are p2wpkh here -> valid)
    privkeys: list[int] = []
    # This again works only with Deterministic wallets, logic has to be adapted for imported wallets
    # also, no checks for negating keys, since we are not dealing with taproot utxos for now
    for coin in coins:
        # This seems to be the most straight forward way to get access to the privkeys as of now
        # Derive the key path from the address
        derivation_index = wallet.get_address_index(coin.address)
        # Get private key (wallet must be unencrypted or already unlocked)
        privkey_bytes, _ = wallet.keystore.get_private_key(derivation_index, password="abcdefg")
        privkeys.append(ecc.string_to_number(privkey_bytes))

    # priv sum ints fit in curve order
    priv_sum: int = sum(privkeys) % ecc.CURVE_ORDER

    # sum of private keys as bytes
    priv_sum_bytes = int.to_bytes(priv_sum, length=32, byteorder='big', signed=False)
    # sum of corresponding public keys. This also checks internally if priv_sum_bytes is valid
    a_sum = ecc.ECPrivkey(priv_sum_bytes)

    # It is somehow not clear from the BIP, if we should use x_only for A_Sum. In the reference, compressed format is used.
    input_hash = bip340_tagged_hash(b"BIP0352/Inputs", lowest_prevout + a_sum.get_public_key_bytes())

    # Next, we construct the shared secret for each group
    # usually, it is possible to have multiple groups/recipients in a transaction.
    # And multiple outputs per group/B_scan for labeling
    # for the sake of testing, we generate only 1 output
    B_scan, B_spend = decode_silent_payment_addr(to_silvio_addr)
    ecdh_shared_secret = (ecc.string_to_number(input_hash) * a_sum.secret_scalar) * B_scan
    k = 0 # this would incremented for multiple groups and/or labels within groups
    t_k = bip340_tagged_hash(b"BIP0352/SharedSecret", ecdh_shared_secret.get_public_key_bytes() + k.to_bytes(4, "big")) # why t_k?
    output_pubkey = B_spend + ((ecc.string_to_number(t_k) % ecc.CURVE_ORDER) * ecc.GENERATOR)


    spk = (b'\x51\x20' + output_pubkey.get_public_key_bytes()[1:])
    output_addr = script_to_address(spk)
    print(f"final addr: {output_addr}")


def decode_silent_payment_addr(address: str, hrp: str = "tsp"):
    _, data = decode(hrp, address)
    if data is None:
        return ecc.ECPubkey(None), ecc.ECPubkey(None) # what to return here? This returns basically two ecc.POINT_AT_INFINITY. Maybe just return None?
    data_bytes = bytes(data)
    B_scan = ecc.ECPubkey(data_bytes[:33])
    B_spend = ecc.ECPubkey(data_bytes[33:])
    return B_scan, B_spend

# method in segwit_addr.decode_segwit_address does kind of the same, but has length restrictions. I got this from bip-reference
def decode(hrp, addr):
    """Decode a segwit address."""
    #hrpgot, data, spec = bech32_decode(addr, ignore_long_length=True)
    dec: DecodedBech32 = bech32_decode(addr, ignore_long_length=True) # this differs slightly from reference
    hrpgot = dec.hrp
    data = dec.data
    if hrpgot != hrp:
        print(f"{hrpgot=} != {hrp=}")
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2:
        print("decoded is None or len(decoded) < 2")
        return (None, None)
    if data[0] > 16:
        print("data[0] > 16")
        return (None, None)
    return (data[0], decoded)
