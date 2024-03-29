#!/usr/bin/env python

import os
import subprocess
import sys

def keep_slience(argv):
  p = subprocess.Popen(['clang++'] + argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  stdout, _ = p.communicate()
  print(stdout.decode(), end='')
  return p.returncode

def violet(argv):
  base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
  prefix = ['-g', '-O1', 
          '-Xclang', '-load', 
          '-Xclang', f'{base}/build/src/compiler_pass/libProtectionPass.so']
          
  suffix = [f'-L{base}/build/src/safe_tcmalloc/tcmalloc', 
            '-ltcmalloc_tcmalloc',
            '-Qunused-arguments',
            '-Wpointer-arith', 
            '-Wpointer-to-int-cast']

  p = subprocess.Popen(['clang++'] + prefix + argv + suffix, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  stdout, _ = p.communicate()
  print(stdout.decode(), end='')
  return p.returncode

def main():
  argv = sys.argv[1:]

  exts = ['.c', '.cc', '.cpp', '.cxx', '.C']
  srcs = [a for a in argv if os.path.splitext(a)[1] in exts]

  if any(a in argv for a in ['-E', '-M', '-MM']):
    return keep_slience(argv)

  elif "-o" not in argv and not srcs:
    return keep_slience(argv)

  else:
    return violet(argv)

if __name__ == '__main__':
	sys.exit(main())