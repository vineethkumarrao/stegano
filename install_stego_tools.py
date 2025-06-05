import os
import platform
import subprocess
import sys

def run_command(command, shell=False):
    """Run a system command."""
    try:
        print(f"Running: {' '.join(command) if isinstance(command, list) else command}")
        subprocess.check_call(command, shell=shell)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)

def install_binwalk():
    """Install Binwalk."""
    print("\n📦 Installing Binwalk...")
    run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    run_command([sys.executable, "-m", "pip", "install", "binwalk"])
    print("✅ Binwalk installation complete.")

def install_exiftool():
    """Install ExifTool."""
    print("\n📦 Installing ExifTool...")
    system = platform.system()
    if system == "Linux":
        distro = ""
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        distro = line.strip().split("=")[1].strip('"')
                        break
        except FileNotFoundError:
            pass
        if distro in ["ubuntu", "debian"]:
            run_command(["sudo", "apt", "update"])
            run_command(["sudo", "apt", "install", "-y", "libimage-exiftool-perl"])
        elif distro in ["fedora"]:
            run_command(["sudo", "dnf", "install", "-y", "perl-Image-ExifTool"])
        else:
            print("Please install ExifTool manually for your distribution.")
    elif system == "Darwin":
        run_command(["brew", "install", "exiftool"])
    elif system == "Windows":
        print("Please download and install ExifTool from https://exiftool.org/")
    else:
        print("Unsupported OS for ExifTool installation.")
    print("✅ ExifTool installation complete.")

def install_zsteg():
    """Install zsteg."""
    print("\n📦 Installing zsteg...")
    system = platform.system()
    if system == "Linux":
        run_command(["sudo", "apt", "update"])
        run_command(["sudo", "apt", "install", "-y", "ruby", "ruby-dev", "build-essential"])
    elif system == "Darwin":
        run_command(["brew", "install", "ruby"])
    elif system == "Windows":
        print("Please install Ruby and RubyGems manually from https://rubyinstaller.org/")
        print("After installation, run 'gem install zsteg' in the Ruby command prompt.")
        return
    else:
        print("Unsupported OS for zsteg installation.")
        return
    run_command(["gem", "install", "zsteg"])
    print("✅ zsteg installation complete.")

def install_stegoveritas():
    """Install StegoVeritas."""
    print("\n📦 Installing StegoVeritas...")
    run_command([sys.executable, "-m", "pip", "install", "stegoveritas"])
    # Install additional dependencies
    run_command(["stegoveritas_install_deps"])
    print("✅ StegoVeritas installation complete.")

def main():
    install_binwalk()
    install_exiftool()
    install_zsteg()
    install_stegoveritas()
    print("\n🎉 All tools have been installed successfully.")

if __name__ == "__main__":
    main()
