.. image:: https://travis-ci.org/VISCHub/ether-examples.svg?branch=master
   :target: https://travis-ci.org/VISCHub/ether-examples
   :alt: Build status

ether-examples
==============

Learning Ethereum by example. To run examples, it's recommended that you use Python 3.6 and above to stay up to date. Code written here tested for Python 3.6 and above only.

How to run locally:

.. code-block:: bash

    $ python -m wallet.decrypt_utc tests/test_v3_scrypt_aes_128_ctr_utc.json
    INFO:root:Preparing to decrypt wallet from UTC file...
    Password in HEX to decrypt the UTC JSON file:
    INFO:root:Successfully decrypted the UTC file: tests/test_v3_scrypt_aes_128_ctr_utc.json

Articles in English
-------------------

Coming soon...

Articles in Vietnamese
----------------------

* `Ethereum Wallet: Giải Mã File UTC JSON <https://medium.com/vischub/ethereum-wallet-giải-mã-file-utc-json-dc62a5c2ce53>`_

Continuous testing
------------------

* Travis: https://travis-ci.org/VISCHub/ether-examples

Alternative libraries
---------------------

This example uses :code:`pycryptodome` library because it has all necessary functions. You can look at other alternatives which provide features separately:

* scrypt: https://pypi.org/project/scrypt/
* cryptography: https://cryptography.io/en/latest/hazmat/primitives/index.html
