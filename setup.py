from setuptools import setup, find_packages

setup(
    name="bhrc_blockchain",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "jinja2",
        "rich",
        "websockets",
        "python-dotenv",
        "ecdsa",
        "pycryptodome",
        "python-jose[cryptography]",
        "bip_utils",
        "mnemonic",
        "pytest",
        "pytest-asyncio"
    ],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "bhrc-wallet = bhrc_blockchain.tools.wallet_cli:main"
        ]
    }
)

