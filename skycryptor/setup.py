from distutils.core import setup, Extension

from subprocess import check_output

python3_headers = check_output(["python3-config", "--includes"])

cryptomagic_module = Extension('cryptomagic', sources = ['cryptomagic.cpp'], include_dirs = ["/usr/include/python3.5m",], extra_compile_args=["-fPIC", "-std=c++11"], language="c++", extra_link_args=['libcryptomagic.a', "-lstdc++", "-lssl", "-lcrypto"])

setup(name='cryptomagic',
      version='0.1.0',
      python_requires='>3',
      description='Hello world module written in C',
      ext_modules=[cryptomagic_module])

