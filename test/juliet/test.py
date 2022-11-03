import os

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
        exit_code = os.system(f"LD_LIBRARY_PATH=~/violet/build/src/safe_tcmalloc/tcmalloc {executable} < dump > res.err 2>&1")

        if exit_code != 0:
            with open('res.err') as f:
                if 'OOB detected' not in f.read():
                    badthings.append(executable)
                    print(f"ERROR: {executable}")

    for badthing in badthings:
        print(f"ERROR: {badthing}")
    
    print(f"BAD/SKIP/ALL {len(badthings)}/{len(skipthings)}/{len(executables)}")

if __name__ == "__main__":
    main()

# make CC=/home/moe/violet/tools/vcc CPP=/home/moe/violet/tools/v++ individuals -j16
# find . | grep ".out" | xargs rm