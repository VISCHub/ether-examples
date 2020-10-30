#!/usr/bin/env python

# Read https://github.com/django-extensions/django-extensions/issues/92
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="VISCWallet",
    version="0.0.5",
    description="Test Wallet for Ether",
    author="Viet Le",
    author_email="vietlq85@gmail.com",
    url="https://github.com/VISCHub/ether-examples",
    packages=["wallet"],
)
