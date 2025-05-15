from collections import defaultdict

from electrum_ecc import ECPubkey, ECPrivkey
from electrum_ecc.util import bip340_tagged_hash

from . import segwit_addr, constants
from .crypto import sha256
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .transaction import PartialTransaction, TxOutpoint, PartialTxOutput
    from .wallet import Standard_Wallet
import electrum_ecc as ecc
"""
    TODO: Get smarter in which cases the input-set could change and find ways to deal with it accordingly.
          - PSBT can be exported/imported.
          - Replace By Fee (RBF): Should either be disallowed when having sp_addresses in tx or shared secrets have to be recalculated.
          - For RBF, see transaction.py[1139]
    TODO: Make final decision about the scope in which we enable silent payments.
          So far, I didn't find a scenario where either standard single-sig or imported single-sig Wallets list
          utxo's of type other than "p2pkh", "p2sh-p2wpkh", "p2wpkh". Therefore, both would be sp-eligible.
          But further investigation is needed. The simplest version for now would be to allow just standard
          single-sig wallets with script-type p2wpkh.
"""

SP_ELIGIBLE_INPUT_TYPES = ["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"] # p2tr is just included for consistency with the bip. Electrum doesn't support spending tr yet.

SILENT_PAYMENT_DUMMY_SPK = bytes(2) + sha256("SilentPaymentDummySpk") # match length of taproot output script

class SilentPaymentUnsupportedWalletException(Exception): pass

class SilentPaymentAddress:
    """
        Takes a silent payment address and decodes into keys
    """
    def __init__(self, address: str, *, net=None):
        if net is None: net = constants.net
        self._encoded = address
        self._B_Scan, self._B_Spend = _decode_silent_payment_addr(net.BIP352_HRP, address)

    @property
    def encoded(self) -> str:
        return self._encoded

    @property
    def B_Scan(self) -> ecc.ECPubkey:
        return self._B_Scan

    @property
    def B_Spend(self) -> ecc.ECPubkey:
        return self._B_Spend

def process_silent_payment_tx(wallet: 'Standard_Wallet', tx: 'PartialTransaction'):
    # Todo: do we check if arguments are None?!?!
    if not wallet.can_send_silent_payment():
        raise Exception(f"silent payments are not supported in this wallet type: {wallet.wallet_type}")
    if tx is None: #if not isinstance(tx, PartialTransaction): #Todo How to deal with circular imports???
        raise ValueError("Expected partial transaction, not {type(tx)}")
    for i in tx.inputs():
        wallet.add_input_info(i) #Todo: this isn't necessary when called from make_unsigned transaction. Overhead?
    if not all([i.is_mine for i in tx.inputs()]):
        raise Exception("All inputs have to be is_mine to process silent payment")

    #TODO: Check witness version <= 1 (although not really possible to happen when all inputs come from this wallet)

    sp_dummy_outputs = [out for out in tx.outputs() if out.is_silent_payment()]
    if not sp_dummy_outputs:
        raise Exception("No silent payment outputs in tx")
    outpoints = [txin.prevout for txin in tx.inputs()]

    # Assumes that all inputs are eligible for shared secret derivation (all inputs are from this wallet only)
    input_privkeys = []
    for txin in tx.inputs():
        der_index = wallet.get_address_index(txin.address)
        privkey, compressed = wallet.keystore.get_private_key(der_index, password=None) #Todo: User gets prompted with pw when signing anyway, so can we just send none?
        assert compressed, "found privkey for uncompressed pubkey"
        input_privkeys.append(ECPrivkey(privkey))

    # Isolate core logic to allow efficient testing
    _derive_sp_outputs(input_privkeys, outpoints, sp_dummy_outputs)


def _derive_sp_outputs(input_privkeys: list[ECPrivkey], outpoints: list['TxOutpoint'], sp_dummy_outputs: list['PartialTxOutput']):
    """
        Derives the final output public keys for silent payment recipients and updates the corresponding dummy spk with the correct spk.
        Args:
            input_privkeys: List of ECPrivkey instances for all eligible transaction inputs.
            outpoints: List of TxOutpoints used for shared secret derivation.
            sp_dummy_outputs: List of PartialTxOutputs each tagged with a SilentPaymentAddress in the `sp_addr` attribute. The spk's of these outputs will be updated accordingly.
    """
    # Ignores negating private keys, since taproot inputs are not yet supported by electrum

    lowest_outpoint: bytes = min([o.serialize_to_network() for o in outpoints])

    a_sum: int = sum([ecc.string_to_number(pk.get_secret_bytes()) for pk in input_privkeys]) % ecc.CURVE_ORDER
    # This edge-case extremely unlikely, but still has to be taken care of. How should error handling look like?
    if a_sum == 0:
        raise Exception("Input private keys sum to zero, cannot derive shared secret") #TODO: Use Custom Exceptions?

    # electrum-ecc takes care of error handling in EC-Multiplication and we receive an assertion error if we sum to infinity
    A_sum: ECPubkey = a_sum * ecc.GENERATOR

    input_hash = bip340_tagged_hash(b"BIP0352/Inputs", lowest_outpoint + A_sum.get_public_key_bytes())

    # create a tuple as value so a link between the recipient and the spk in the output can be made
    silent_payment_groups: dict[ECPubkey, list[tuple[ECPubkey, 'PartialTxOutput']]] = {}

    for sp_dummy_output in sp_dummy_outputs:
        recipient: SilentPaymentAddress = sp_dummy_output.sp_addr
        B_Scan, B_m = recipient.B_Scan, recipient.B_Spend
        if B_Scan in silent_payment_groups:
            silent_payment_groups[B_Scan].append((B_m, sp_dummy_output))
        else:
            silent_payment_groups[B_Scan] = [(B_m, sp_dummy_output)]

    for B_scan, B_m_values in silent_payment_groups.items():
        ecdh_shared_secret = ecc.string_to_number(input_hash) * a_sum * B_scan
        k = 0
        for B_m, output in B_m_values:
            t_k = bip340_tagged_hash(b"BIP0352/SharedSecret", ecdh_shared_secret.get_public_key_bytes() + k.to_bytes(4, "big"))
            # ECPrivKey(t_k) checks (1 < t_k < n), multiplies it by G and behaves like a pub key for addition
            P_km = B_m + ECPrivkey(t_k) # B_m + t_k * G
            # directly update the corresponding scriptpubkey.
            # Like this we make sure, the generated spk's belong to the correct amount entered by the user
            output.scriptpubkey = (b'\x51\x20' + P_km.get_public_key_bytes()[1:])
            k += 1

def is_silent_payment_address(addr: str, *, net=None) -> bool:
    if net is None: net = constants.net
    try:
        _decode_silent_payment_addr(net.BIP352_HRP, addr)
        return True
    except Exception:
        return False

def _decode_silent_payment_addr(hrp: str, address: str) -> tuple[ecc.ECPubkey, ecc.ECPubkey]:
    """Decodes a Silent Payment address (version 0 only) and returns (B_scan, B_spend) pubkeys."""
    dec = segwit_addr.bech32_decode(address, ignore_long_length=True)
    if dec.hrp != hrp or dec.data is None:
        raise ValueError(f"Invalid HRP or malformed silent payment address: {address}")

    version = dec.data[0]
    decoded = segwit_addr.convertbits(dec.data[1:], 5, 8, False)
    if decoded is None:
        raise ValueError("Bech32 conversion failed")

    if version == 0:
        if len(decoded) != 66:
            raise ValueError("Silent payment v0 must contain exactly 66 bytes")
    elif 1 <= version <= 30:
        raise NotImplementedError(f"Silent payment version {version} not yet supported")
    elif version == 31:
        raise ValueError("Silent payment version 31 is reserved and invalid")
    else:
        raise ValueError(f"Unknown silent payment version: {version}")

    try:
        B_scan = ecc.ECPubkey(bytes(decoded[:33]))
        B_spend = ecc.ECPubkey(bytes(decoded[33:]))
    except Exception as e:
        raise ValueError(f"Invalid public key(s) in silent payment address: {e}")

    return B_scan, B_spend


