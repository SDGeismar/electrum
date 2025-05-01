from typing import Sequence

from . import constants
from .transaction import PartialTxInput, TxOutpoint
from .segwit_addr import bech32_decode, convertbits, DecodedBech32
import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash
from .bitcoin import taproot_output_script, script_to_address, address_to_script, taproot_tweak_pubkey, construct_script, decode_silent_payment_addr

# TODO: Check in bitcoin.py "DummyAddress" and what its used for. Maybe we find something useful for input selection with dummy addresses
# TODO: Dive into plugins. e.g. wallet.make_unsigned_transaction runs a hook in the end. Maybe this would be a place to calculate the output addresses.

class SilentPaymentAddress:
    """
        Takes a silent payment address and decodes into keys
    """
    B_Spend: ecc.ECPubkey
    B_Scan: ecc.ECPubkey
    address: str
    def __init__(self, address: str, net = None):
        if net is None:
            net = constants.net
        self.address = address
        self.B_Scan, self.B_Spend = decode_silent_payment_addr(address)


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
