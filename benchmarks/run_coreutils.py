import os
import subprocess
import sys
import argparse
import json

current_file_dir = os.path.dirname(os.path.realpath(__file__))
coreutils_url = "https://git.savannah.gnu.org/git/coreutils.git"
coreutils_path = current_file_dir + "/coreutils/"
env = os.environ.copy()


def load_config(path):
    with open(path) as f:
        return json.load(f)

def update_interpreter(current_path, loader_path):
    dir_list = os.listdir(current_path)
    for dir in dir_list:
        new_dir = current_path + "/" + dir
        if(new_dir == "env"):
            continue
        if(os.path.isdir(new_dir)):
            update_interpreter(new_dir, loader_path)
        else:
            result = subprocess.run(["file", new_dir], capture_output=True, text=True, check=True)
            if("ELF" in result.stdout and "interpreter" in result.stdout):
                try:
                    result = subprocess.run(["patchelf", "--set-interpreter", loader_path, new_dir], check=True)
                except Exception as e:
                    print(f"[{new_dir}] {e}")


def run_test():
    print(env["PATH"])
    subprocess.run(["make", "check"], cwd=coreutils_path, check=True, env=env)


def main():
    parser = argparse.ArgumentParser(description="Build and test coreutils")
    parser.add_argument("config", help="Path to config file")
    parser.add_argument("-b", "--build", action="store_true",
                        help="Build the coreutil tests before running them")

    args = parser.parse_args()

    if not args.config:
        print("no config file provided")
        return
    
    config = load_config(args.config)
    env["SECPOLINE"] = config["secpoline_path"]
    base_loader_path = config["base_loader_path"]
    secpoline_loader_path = config["secpoline_loader_path"]

    if not os.path.exists(coreutils_path):
        subprocess.run(["git", "clone", coreutils_url, coreutils_path])

    if args.build:
        print("building coreutils")
        subprocess.run(["./bootstrap"], cwd=coreutils_path)
        subprocess.run(["./configure", "--disable-generate-manpages", "--no-discard-stderr"], cwd=coreutils_path)
        subprocess.run(["make", "clean"], cwd=coreutils_path)
        subprocess.run(["make", f"-j{os.cpu_count()}"], cwd=coreutils_path)


    update_interpreter(coreutils_path+"/src/", secpoline_loader_path)
    #update_interpreter(coreutils_path+"/src/", base_loader_path)
    run_test()

main()
