"""
This is a simple [Modal](https://modal.com/) used to test `rstrace` on NVIDIA GPUs.

It installs `rstrace` at a given commit and then runs a number of test programs specified
in the `gpu.sh` script.

Currently the only test requirement is that rstrace exits zero on each test program and rstrace
completes all programs within the timeout.

In future it'd be better to assert on specific features of the trace output.
"""
import os
import subprocess

import modal

# Create a container image which can build `rstrace` from source as well
# as run PyTorch programs.
image = modal.Image.debian_slim().pip_install("torch").apt_install(
    "build-essential",
    "curl",
    "pkg-config",
    "libssl-dev",
    "git",
    "clang",
).run_commands(
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
)


app = modal.App(
    name="rstrace-gpu-ci-testing", 
    image=image,
    # A Github token is required to clone a private repo. rstrace is now a public repository,
    # so this secret is no longer required.
    secrets=[modal.Secret.from_name("rstrace-github-token")],
)

@app.function(gpu="any", cpu=(1, 16),timeout=800, scaledown_window=2)
def test_on_gpu(commit_sha: str = ""):
    # Grab the Github token populated in the environment by the use of a modal.Secret.
    token = os.environ["GITHUB_TOKEN"]
    address = f"https://{token}@github.com/thundergolfer/rstrace.git"
    if commit_sha:
        address = f"{address}#commit={commit_sha}"

    subprocess.run(f"git clone {address}", shell=True, check=True)
    subprocess.run(f"cd rstrace && git checkout {commit_sha}", shell=True, check=True)
    subprocess.run("/root/.cargo/bin/cargo install --path ./rstrace/crates/rstrace", shell=True, check=True)
    subprocess.run("cd rstrace/tests && ./gpu.sh", shell=True, check=True)


@app.local_entrypoint()
def main(commit_sha: str = ""):
    if commit_sha:
        print(f"Testing commit {commit_sha}")
    test_on_gpu.remote(commit_sha)
