from setuptools import setup, find_packages
import codecs

with codecs.open("README.rst", "r", "utf-8") as fd:
    long_description = fd.read()

setup(
    name="ether-examples",
    version="0.2.1",
    description="Learn Ethereum by examples",
    long_description=long_description,
    author="Viet Le",
    author_email="vietlq85@gmail.com",
    url="https://github.com/VISCHub/ether-examples",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "decrypt_utc_hex=ether_examples.decrypt_utc:run_decrypt_utc_file_hex_pwd"
        ],
    },
    install_requires=["pycryptodome"],
    keywords=["ethereum cryptography examples"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
