#
import os
import shutil
#
from distutils.core import setup, Extension
from distutils.command.build_py import build_py
from distutils.command.clean import clean
from subprocess import check_output

#
python3_headers = check_output(["python3-config", "--includes"])

#
cryptomagic_module = Extension('cryptomagic', sources = ['skycryptor/cryptomagic.cpp'], include_dirs = ["/usr/include/python3.5m",], extra_compile_args=["-fPIC", "-std=c++11"], language="c++", extra_link_args=['skycryptor/libcryptomagic.a', "-lstdc++", "-lssl", "-lcrypto"])

#
class BuilderClass(build_py):
    LIBNAME="cryptomagic"
    LIBFILE="lib" + LIBNAME + ".a"
    SOURCE_DIR=os.getcwd()
   

    def run(self):
      os.system("git clone https://github.com/skycryptor/cryptomagic.git {}".format(self.LIBNAME)) 
      os.chdir("{}/{}".format(self.SOURCE_DIR, self.LIBNAME))
      if os.path.exists("build"):
          shutil.rmtree("build", ignore_errors=True)
      os.mkdir("build")
      os.chdir("build")
             
      os.system("cmake ..")
      os.system("make -j4")
      os.system("cp {} {}/skycryptor".format(self.LIBFILE, self.SOURCE_DIR))
      os.chdir("{}".format(self.SOURCE_DIR))
      shutil.rmtree("{}".format(self.LIBNAME))

class CleanClass(clean):
    SOURCE_DIR=os.getcwd()
    
    def run(self):
        os.system("cp build/lib.linux-x86_64-2.7/cryptomagic.so {}/skycryptor".format(self.SOURCE_DIR))
        shutil.rmtree("{}".format("build"))

#
setup(name='skycryptor',
      version='0.1.0',
      python_requires='>3', 
      description='Python sdk for SkyCryptor API functionality.',
      ext_modules=[cryptomagic_module],
      packages=['skycryptor', 'tests'],
      cmdclass={'build_py': BuilderClass, 'clean': CleanClass}
      )
