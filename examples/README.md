# Examples

Install the package first. Run `python examples/generate-demo.py --output demo-workspace` or `research-integrity demo --output demo-workspace`. Each writes the same three small synthetic files and a walkthrough in a newly created directory. Run the walkthrough in a terminal for the passphrase prompts. [Signed demonstration](../README.md#try-a-signed-comparison)

Run `python examples/benchmark.py 4 16 64` to generate disposable files of 4, 16, and 64 MiB, then measure inventory time and traced Python allocation. The script prints one JSON object per size. [Measurement method](../docs/evaluation.md)
