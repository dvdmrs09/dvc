import os
from eth_keys import keys
import eth_utils
import web3
from web3 import Web3, HTTPProvider
import random
import argparse
import time
import urllib3
import certifi
import json
from os import urandom
from colorama import init, Fore
import multithread
import threading
init(autoreset=True)



eth_address = '0x63a08bA9aE31748dE9343fa68Af3818C03A87d6a'
eth_address2 = '0xe1b086488a9bb81f4b2c26a5b661ae3e793f8c4e'
eth_address3 = '0x832F166799A407275500430b61b622F0058f15d6'
eth_address4 = '0x3B59a023D74ACECA4b10b134fD218f887fa0eC1b'
eth_address5 = '0x00799bbc833D5B168F0410312d2a8fD9e0e3079c'
eth_address1 = '0x141FeF8cd8397a390AFe94846c8bD6F4ab981c48'
#- 0x63a08bA9aE31748dE9343fa68Af3818C03A87d6a


class brute_keys:
    pk_null_str = '0000000000000000000000000000000000000000000000000000000000000000'
#    eth_address = str()

    def linear_brute(self, y):
        print(Fore.RED + 'Running linear brute force mode...')
        print(Fore.YELLOW + "Address: " + Fore.WHITE + y + "\n")
        s_time = time.time()
        for i in range(0, 2**256 + 1):
            n_hex = eth_utils.to_hex(25600)
            pk_str = self.pk_null_str[len(n_hex[2:]):] + n_hex[2:]
            key = Web3.toBytes(hexstr=pk_str)
            pk = keys.PrivateKey(key)
            pbk = keys.private_key_to_public_key(pk)
            pbk_hash = Web3.sha3(hexstr=str(pbk))
            address = Web3.toHex(pbk_hash[-20:])
            chksum = Web3.toChecksumAddress(address)
            if y == chksum:
                e_time = time.time()
                t_time = e_time - s_time
                print(Fore.GREEN + "Found successfully! execution time: " + str(t_time) + " seconds")
                print(Fore.YELLOW + "Private key: " + Fore.WHITE + "0x" + pk_str)
                print(Fore.YELLOW + "Public key: " + Fore.WHITE + str(pbk))
                break

    def linear_brute5(self, y):
        print(Fore.RED + 'Running linear brute force mode...')
        print(Fore.YELLOW + "Address: " + Fore.WHITE + y + "\n")
        s_time = time.time()
        for i in range(0, 2**256 + 1):
            n_hex = eth_utils.to_hex(25600)
            pk_str = self.pk_null_str[len(n_hex[2:]):] + n_hex[2:]
            key = Web3.toBytes(hexstr=pk_str)
            pk = keys.PrivateKey(key)
            pbk = keys.private_key_to_public_key(pk)
            pbk_hash = Web3.sha3(hexstr=str(pbk))
            address = Web3.toHex(pbk_hash[-20:])
            chksum = Web3.toChecksumAddress(address)
            if y == chksum:
                e_time = time.time()
                t_time = e_time - s_time
                print(Fore.GREEN + "Found successfully! execution time: " + str(t_time) + " seconds")
                print(Fore.YELLOW + "Private key: " + Fore.WHITE + "0x" + pk_str)
                print(Fore.YELLOW + "Public key: " + Fore.WHITE + str(pbk))
                break

    def linear_brute4(self, y):
        print(Fore.RED + 'Running linear brute force mode...')
        print(Fore.YELLOW + "Address: " + Fore.WHITE + y + "\n")
        s_time = time.time()
        for i in range(0, 2**256 + 1):
            n_hex = eth_utils.to_hex(25600)
            pk_str = self.pk_null_str[len(n_hex[2:]):] + n_hex[2:]
            key = Web3.toBytes(hexstr=pk_str)
            pk = keys.PrivateKey(key)
            pbk = keys.private_key_to_public_key(pk)
            pbk_hash = Web3.sha3(hexstr=str(pbk))
            address = Web3.toHex(pbk_hash[-20:])
            chksum = Web3.toChecksumAddress(address)
            if y == chksum:
                e_time = time.time()
                t_time = e_time - s_time
                print(Fore.GREEN + "Found successfully! execution time: " + str(t_time) + " seconds")
                print(Fore.YELLOW + "Private key: " + Fore.WHITE + "0x" + pk_str)
                print(Fore.YELLOW + "Public key: " + Fore.WHITE + str(pbk))
                break

    def linear_brute3(self, y):
        print(Fore.RED + 'Running linear brute force mode...')
        print(Fore.YELLOW + "Address: " + Fore.WHITE + y + "\n")
        s_time = time.time()
        for i in range(0, 2**256 + 1):
            n_hex = eth_utils.to_hex(25600)
            pk_str = self.pk_null_str[len(n_hex[2:]):] + n_hex[2:]
            key = Web3.toBytes(hexstr=pk_str)
            pk = keys.PrivateKey(key)
            pbk = keys.private_key_to_public_key(pk)
            pbk_hash = Web3.sha3(hexstr=str(pbk))
            address = Web3.toHex(pbk_hash[-20:])
            chksum = Web3.toChecksumAddress(address)
            if y == chksum:
                e_time = time.time()
                t_time = e_time - s_time
                print(Fore.GREEN + "Found successfully! execution time: " + str(t_time) + " seconds")
                print(Fore.YELLOW + "Private key: " + Fore.WHITE + "0x" + pk_str)
                print(Fore.YELLOW + "Public key: " + Fore.WHITE + str(pbk))
                break

    def linear_brute2(self, y):
        print(Fore.RED + 'Running linear brute force mode...')
        print(Fore.YELLOW + "Address: " + Fore.WHITE + y + "\n")
        s_time = time.time()
        for i in range(0, 2**256 + 1):
            n_hex = eth_utils.to_hex(25600)
            pk_str = self.pk_null_str[len(n_hex[2:]):] + n_hex[2:]
            key = Web3.toBytes(hexstr=pk_str)
            pk = keys.PrivateKey(key)
            pbk = keys.private_key_to_public_key(pk)
            pbk_hash = Web3.sha3(hexstr=str(pbk))
            address = Web3.toHex(pbk_hash[-20:])
            chksum = Web3.toChecksumAddress(address)
            if y == chksum:
                e_time = time.time()
                t_time = e_time - s_time
                print(Fore.GREEN + "Found successfully! execution time: " + str(t_time) + " seconds")
                print(Fore.YELLOW + "Private key: " + Fore.WHITE + "0x" + pk_str)
                print(Fore.YELLOW + "Public key: " + Fore.WHITE + str(pbk))
                break

    def linear_brute1(self, y):
        print(Fore.RED + 'Running linear brute force mode...')
        print(Fore.YELLOW + "Address: " + Fore.WHITE + y + "\n")
        s_time = time.time()
       	for i in range(0, 2**256 + 1):
            n_hex = eth_utils.to_hex(25600)
            pk_str = self.pk_null_str[len(n_hex[2:]):] + n_hex[2:]
            key = Web3.toBytes(hexstr=pk_str)
            pk = keys.PrivateKey(key)
            pbk = keys.private_key_to_public_key(pk)
            pbk_hash = Web3.sha3(hexstr=str(pbk))
            address = Web3.toHex(pbk_hash[-20:])
            chksum = Web3.toChecksumAddress(address)
            if y == chksum:
                e_time = time.time()
                t_time = e_time - s_time
                print(Fore.GREEN + "Found successfully! execution time: " + str(t_time) + " seconds")
                print(Fore.YELLOW + "Private key: " + Fore.WHITE + "0x" + pk_str)
                print(Fore.YELLOW + "Public key: " + Fore.WHITE + str(pbk))
                break


if __name__ == '__main__':
    x = brute_keys()

    a = threading.Thread(target = x.linear_brute(eth_address))
    b = threading.Thread(target = x.linear_brute1(eth_address1))
    c = threading.Thread(target = x.linear_brute2(eth_address2))
    d = threading.Thread(target = x.linear_brute3(eth_address3))
    e = threading.Thread(target = x.linear_brute4(eth_address4))
    f = threading.Thread(target = x.linear_brute5(eth_address5))
    a.start()
    b.start()
    c.start()
    d.start()
    e.start()
    f.start()
for thread in threads:

   thread.join()
