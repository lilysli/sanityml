# sanityML

> 🔍 A quick sanity check for ML projects  
> Scans Python files, Jupyter notebooks, serialized models, and dependencies for common security risks.

`sanityML` is a lightweight tool to help you **test downloaded or shared ML code before running it**. It scans a given folder and looks for:
- `.py` and `.ipynb` files (for unsafe patterns),
- Serialized models (`.pt`, `.pth`, `.pkl`, `.joblib`, `.h5`),
- **One** `requirements.txt` file (at the root of the scanned folder — used for dependency vulnerability checks).

💡 It only uses the top-level `requirements.txt` file. All Python/notebook/model files *within the folder and its subdirectories* are still scanned.

It is useful for trying out GitHub repos or HuggingFace code and auditing your own hobby projects.

---

## 🚀 Quick Start

The recommended way to install and run `sanityML`:

```bash
# 1. Create a new environment using for example conda
conda create -n sanityml python=3.11 -y

# 2. Activate it
conda activate sanityml

# 3. Install sanityml directly from GitHub
pip install "git+https://github.com/lilysli/sanityml.git"

# 4. Check that it works
sanityml --help

# 5. Scan a project folder (you can also use the test folder I have included)
sanityml ./your-ml-project/
