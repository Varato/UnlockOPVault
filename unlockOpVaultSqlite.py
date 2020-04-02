import os
import sqlite3
import json
import hmac
import hashlib
import pprint
import struct
import argparse
from pathlib import Path
from getpass import getpass
from datetime import datetime
from collections import namedtuple, OrderedDict
from typing import Dict

from Crypto.Cipher import AES
from Crypto.Protocol import KDF



def unlock(dbfile: Path, n: int):
    """
    unlock a vault stored int dataPath/OnePassword.sqlite.
    n: number of items to reveal (order is defined in the database)
    """
    pp = pprint.PrettyPrinter()
    if os.path.basename(dbfile) != "OnePassword.sqlite":
        raise ValueError("only support OnePassword.sqlite format")

    profile = fetch_profile(dbfile)
    mp = getpass("Please enter your master password: ")
    derivedKeys = derive_keys(mp, profile['salt'], profile['iterations'])
    masterKeys = decrypt_masterkey(profile['master_key_data'], derivedKeys)
    print("Vault unlocked! Master Key only exists in RAM while this program runs.")
    overviewKeys = decrypt_overviewkey(profile['overview_key_data'], derivedKeys)

    flag = input(f'Reveal {n} items? (y):').lower().strip()

    if flag in ('y', ''):
        itemGen = fetch_items(dbfile)
        for i, item in enumerate(itemGen):
            o = decrypt_item_overview(item['overview_data'], overviewKeys)
            itemKeys = decrypt_itemkey(item['key_data'], masterKeys)
            d = decrypt_item_data(item['data'], itemKeys)
            print(f"ITEM {i+1} {item['uuid']}")
            plainItem = OrderedDict()
            plainItem['overview'] = json.loads(o)
            plainItem['created'] = unixtime2utc(item['created_at'])
            plainItem['updated'] = unixtime2utc(item['updated_at'])
            plainItem['data'] = json.loads(d)
            plainItem['trashed'] = item['trashed']
            pp.pprint(plainItem)
            if i >= n-1: break



def fetch_profile(dbfile: str) -> Dict:
    profile = {}
    with sqlite3.connect(dbfile) as conn:
        conn = sqlite3.connect(dbfile)
        cur = conn.cursor()
        # fetch the 'profiles' table creation query to get all columns
        cur.execute("""SELECT sql FROM sqlite_master 
                       WHERE tbl_name = 'profiles' AND type = 'table'
                    """)
        ans = cur.fetchone()[0]
        columns = filter(
            lambda c: 
                not c.strip().split(' ')[0].upper() in ('UNIQUE', 'FOREIGN', 'PRIMARY', 'UNIQUE', 'CHECK'), 
            ans[ans.find('(')+1: ans.rfind(')')].split(','))
        
        keys = [c.strip().split(' ')[0] for c in columns]
        cur.execute("SELECT * FROM profiles")
        values = cur.fetchone()
        
    return dict(zip(keys, values))


def fetch_items(dbfile: str) -> Dict:
    """
    in OnePassword.sqlite, item overviews, item keys are in table 'items',
    item data is in table 'item_details'
    """
    with sqlite3.connect(dbfile) as conn:
        cur = conn.cursor()
        cur.execute("""SELECT sql FROM sqlite_master 
                       WHERE tbl_name = 'items' AND type = 'table'
                    """)
        ans = cur.fetchone()[0]
        columns = filter(
            lambda c: 
                not c.strip().split(' ')[0].upper() in ('UNIQUE', 'FOREIGN', 'PRIMARY', 'UNIQUE', 'CHECK'), 
            ans[ans.find('(')+1: ans.rfind(')')].split(','))
        keys = [c.strip().split(' ')[0] for c in columns]
        cur.execute("SELECT * FROM items")

        valuess = cur.fetchall()
        print(f"{len(valuess)} items in the vault")
        for values in valuess:
            item = dict(zip(keys, values))
            cur.execute(f"SELECT data FROM item_details WHERE item_id = {item['id']}")
            item['data'] = cur.fetchone()[0]
            yield item


DerivedKeys = namedtuple("DerivedKeys", ("cryptoKey", "hmacKey"))
def derive_keys(masterPassoword: str, salt:bytes, iterations:int) -> DerivedKeys:
    """
    In OPVault format, the key derivation parameters, except Master Password,
    are all in 'profile'. In iCloud/Dropbox synced format, the profile is stored 
    as `profile.js` as a json object. In MacOS local format, the profile is a
    table in a SQLite database called 'OnePassword.sqlite', usually located at 
    ~/Library/Group Containers/2BUA8C4S2C.com.agilebits/Library/Application Support/1Password/Data.

    Because we don't use 2skd in OpVault, here it is fairly simple.
    The algorithm used here is PBKDF2-HMAC-SHA512, with the plain
    'salt' in profile. See https://support.1password.com/opvault-design/#key-derivation 
    for more information.

    The derived cryptoKey and hmacKey are used to encrypt/decrypt 
    and hmac-authenticate masterKey and overviewKey in profile.

    input:
        masterpassword: the user entered master password string
        salt: the base64 encoded string directly from profile.js. 
            Thus it need to be decoded here
    """
    # encode master password as a utf-8 null terminated string.
    mp = (masterPassoword + '\0').encode('utf-8')
    # decode the salt into bytes

    dk = KDF.PBKDF2(
        password=mp, 
        salt=salt, 
        dkLen=64, 
        count=iterations, 
        prf=hmac_sha512)

    return DerivedKeys(cryptoKey=dk[0:32], hmacKey=dk[32:])

# After the DerivedKeys are obtained, we are going to decrypt the master keys and overview keys.
# Because they are opdata object (), we can firstly implement a general decryption function for opdata.
def decrypt_opdata(data: bytes, cryptoKey: bytes, hmacKey: bytes) -> bytes:
    """
    see https://support.1password.com/opvault-design/#opdata01 for details.
    In a opdata entry, the first 8 bytes are always b"opdata01".
    The next 8 bytes form a unsinged int64 to indicate the length of the plaintext in bytes.
    The next 16 bytes form initialization vector (IV) for AES256 CBC encryption via the cryptoKey.
    The last 32 bytes form the hmac code.
    The rest bytes in the middle form the ciphertext. But notice the after decrypting the ciphertext,
    the plaintext obtained is longer than the length indicated by the second 8 bytes. This is because
    some random bytes are prepended for more security.
    """

    header = data[0:8]
    if header != b"opdata01":
        raise ValueError("decrypt_opdata is decrypting a non-opdata format string")
    length = struct.unpack('<Q', data[8:16])[0]
    IV = data[16:32]
    mac = data[-32:]

    # here we first autheticate the MAC code. 
    # If it fails, then either the derived key is incorrect, or the data is tampered.
    computed_mac = hmac_sha256(hmacKey, data[0:-32])
    if mac != computed_mac:
        raise ValueError("HMAC authetication failed. Either key is incorrect or data is tampered.")

    # decrypt
    ciphertext = data[32:-32]
    cipher = AES.new(cryptoKey, AES.MODE_CBC, IV=IV)
    plaintext = cipher.decrypt(ciphertext)

    # remove the random prepending
    return plaintext[-length:]


MasterKeys = namedtuple("MasterKeys", ("cryptoKey", "hmacKey"))
def decrypt_masterkey(masterKeyEntry: bytes, derivedKeys: DerivedKeys) -> MasterKeys:
    """
    Uses derivedKeys to decrypt the masterKey in profile.js.

    masterKey: the base64 decoded data.
    """
    mkMaterial = decrypt_opdata(masterKeyEntry, derivedKeys.cryptoKey, derivedKeys.hmacKey)
    assert len(mkMaterial) == 256

    # the decrypted mkMaterial is of 256 Bytes, which cannot be used in AES256. 
    # AES256 uses 256-bit key (32 bytes). OpVault takes the mkMaterial and SHA512 it 
    # so the resulting 64 bytes are divided into master crytoKey and hmacKey.
    mk = hashlib.sha512(mkMaterial).digest()

    return MasterKeys(cryptoKey=mk[0:32], hmacKey=mk[32:])


OverviewKeys = namedtuple("OverviewKeys", ("cryptoKey", "hmacKey"))
def decrypt_overviewkey(overviewKeyEntry: bytes, derivedKeys: DerivedKeys) -> OverviewKeys:
    """
    similar to decryption of master key, except the plaintext is only 64bytes.
    """
    okMaterial = decrypt_opdata(overviewKeyEntry, derivedKeys.cryptoKey, derivedKeys.hmacKey)
    assert len(okMaterial) == 64
    ok = hashlib.sha512(okMaterial).digest()
    return OverviewKeys(cryptoKey=ok[0:32], hmacKey=ok[32:])


# After having the overview Keys, we can decrypt the overview of each item.
def decrypt_item_overview(overview: bytes, overviewKeys: OverviewKeys) -> bytes:
    # the overview is an opdata object
    return decrypt_opdata(overview, overviewKeys.cryptoKey, overviewKeys.hmacKey)


# To reveal the substantial item data, we need to decrypt item key first
ItemKeys = namedtuple("ItemKeys", ('cryptoKey', "hmacKey"))
def decrypt_itemkey(itemKeyEntry: bytes, masterKeys: MasterKeys) -> ItemKeys:
    """
    After base64 decoding, the itemKeyEntry is of 112 bytes.
    112 = 16(IV) + 64 + 32(MAC)    
    """
    IV = itemKeyEntry[0:16]
    mac = itemKeyEntry[-32:]
    computed_mac = hmac_sha256(masterKeys.hmacKey, itemKeyEntry[0:-32])
    if mac != computed_mac:
        raise ValueError("HMAC authetication failed on an itemKey")
    ciphertext = itemKeyEntry[16:-32]
    cipher = AES.new(masterKeys.cryptoKey, AES.MODE_CBC, IV=IV)
    plaintext = cipher.decrypt(ciphertext)
    return ItemKeys(cryptoKey=plaintext[0:32], hmacKey=plaintext[32:])


def decrypt_item_data(data: bytes, itemKeys: ItemKeys) -> bytes:
    return decrypt_opdata(data, itemKeys.cryptoKey, itemKeys.hmacKey)


# Simple wrapper of HMAC functions. They will be used to compute HMACs and
# derive keys from master password.
def hmac_sha512(key, msg):
    return hmac.new(key, msg, hashlib.sha512).digest()


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def b64decode(data:str) -> bytes:
    return base64.b64decode(data.encode('ascii'))


def unixtime2utc(unixTime: int) -> str:
    return datetime.utcfromtimestamp(unixTime).strftime('%Y-%m-%d')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='path', type=str, help="path to OnePassword.sqlite", 
        default = os.path.expanduser('~/Library/Group Containers/2BUA8C4S2C.com.agilebits/Library/Application Support/1Password/Data/OnePassword.sqlite'))
    parser.add_argument('-n', dest='n', type=int, help="number of items to reveal", default=5)
    args = parser.parse_args()

    unlock(args.path, args.n)