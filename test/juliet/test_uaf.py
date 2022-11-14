import os
import time
import socket
import subprocess

def main():
    executables = []
    badthings = []

    with open("dump", 'w') as f:
        f.write('100 ' * 0x1000)

    for path, dirs, files in os.walk('testcases'):
        for file in files:
            if file.endswith('.out'):
                executables.append(os.path.join(path, file))
    
    for idx, executable in enumerate(sorted(executables)):
        print(f"Running {idx}.{executable}")
        
        with open('dump') as f:
            p = subprocess.Popen(
                [f'{executable}'], 
                env={'LD_LIBRARY_PATH': '/home/moe/violet/build/src/safe_tcmalloc/tcmalloc'},
                stdin=f,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        
        p.wait()

        stdout, stderr = p.communicate()

        # print(stdout)
        # print(stderr)
        
        if b'Calling good' in stdout and b'Finished good' not in stdout:
            print (f"FN: {executable}")
            badthings.append(executable)
        elif b'Calling bad' in stdout and b'Finished bad' not in stdout and b'detected' not in stderr:
            print (f"ERR: {executable}")
            badthings.append(executable)
    
    for badthing in badthings:
        print(f"ERROR: {badthing}")
    
    print(f"BAD/ALL {len(badthings)}/{len(executables)}")

if __name__ == "__main__":
    main()

# make CC=/home/moe/violet/tools/vcc CPP=/home/moe/violet/tools/v++ individuals -j16
# find . | grep "\.out$" | xargs rm