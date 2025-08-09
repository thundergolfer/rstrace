import os
import subprocess

import modal

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
    secrets=[modal.Secret.from_name("rstrace-github-token")],
)

@app.function(gpu="any", timeout=240, scaledown_window=2)
def test_on_gpu(commit_sha: str = ""):
    token = os.environ["GITHUB_TOKEN"]
    address = f"https://{token}@github.com/thundergolfer/rstrace.git"
    if commit_sha:
        address = f"{address}#commit={commit_sha}"

    subprocess.run(f"git clone {address}", shell=True, check=True)
    subprocess.run(f"cd rstrace && git checkout {commit_sha}", shell=True, check=True)
    subprocess.run("/root/.cargo/bin/cargo install rstrace", shell=True, check=True)
    subprocess.run("cd rstrace/tests && ./gpu.sh", shell=True, check=True)


@app.local_entrypoint()
def main(commit_sha: str = ""):
    if commit_sha:
        print(f"Testing commit {commit_sha}")
    test_on_gpu.remote(commit_sha)
