from setuptools import setup
from setuptools_rust import Binding, RustExtension

try:
    with open('README.md', mode="r") as f:
        readme = f.read()
except Exception:
    with open('README.md', mode="r", encoding='utf8', errors='ignore') as f:
        readme = f.read()

#version = '0.1.0-unknown'
#with open("Cargo.toml", mode="r") as fp:
#    for line in fp.read().split("\n"):
#        if not line.startswith("version"):
#            continue
#        _, version = line.split("=", 2)
#        version = version.lstrip().rstrip()
#        version = version[1:]
#        version = version[:-1]
#        break

setup(
    name="multi-party-schnorr",
    url="https://github.com/namuyan/multi-party-schnorr",
    long_description=readme,
    long_description_content_type='text/markdown',
    version="0.1.9",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Rust",
    ],
    rust_extensions=[
        RustExtension("multi_party_schnorr", binding=Binding.PyO3)
    ],
    # rust extensions are not zip safe, just like C-extensions.
    python_requires='>=3.5',
    include_package_data=True,
    license="GPL-3",
    zip_safe=False,
)
