# 🤔 How to Contribute to DeNuitkanizator

**Thank you for your interest in the project!** I welcome any improvements — whether it’s fixing a bug, adding a new feature, or enhancing the documentation.

## ❓ What You Can Do

* **Report a bug:** open an [Issue](https://github.com/2M12/DeNuitkanizator/issues) with a description of the problem. Please attach:
  * The version of DeNuitkanizator
  * The Python version (if you’re running a `.py` script)
  * An example `.exe` file where the error occurs (if possible)
  * A log file from the `DeNuitkanizator_Output/` folder
* **Propose a new feature:** create an Issue with your idea and a description of how it should work. Suggestions for improving Nuitka build detection are especially welcome.
* **Submit a Pull Request:** fork the repository, make the changes, and submit a PR.

## 🔀 Pull Request Process

1. Fork the repository.
2. Create a branch: `feature/name` or `fix/name`.
3. Make the changes.
4. Test:
  * Run `python DeNuitkanizator.py` on a test `.exe`
  * Check that all artifacts are extracted correctly
  * Make sure the output in `summary.txt` is generated without errors
5. Submit a Pull Request with a description:
  * What was done
  * A link to the related Issue (if any)
  * What it was tested on (Nuitka version, build type — OneFile/standalone)

## ❗ Code Requirements

* Python 3.11+
* Dependencies: `pefile`, `colorama` (required); `capstone`, `zstandard` (optional)
* Compliance with PEP 8 (desirable but not mandatory)
* Comments for new functions and complex sections:
  * What the block does
  * What parameters it accepts
  * What it returns
* Do not break backward compatibility with Python 3.11
* Optional dependencies must remain optional — the program must not crash if they are missing (use `try/except ImportError`)
* Testing before submitting a PR is mandatory

## ➡️ Priority Areas

* **Improving Nuitka build detection:** new signatures, heuristics for Nuitka versions with aggressive LTO optimization
* **Extending Python version support:** adding signatures for Python 3.12+
* **Improving bytecode extraction:** more accurate search for magic numbers, reconstructing `.pyc` structure from fragments
* **ELF/Mach‑O support:** analyzing Nuitka builds for Linux and macOS
* **Enhancing the disassembly part:** smarter entry point analysis, searching for Python C API calls (if Capstone is available)
* **HTML report:** generating a structured report as an addition to `summary.txt`
* **Speed optimization:** profiling on large files (100+ MB), identifying bottlenecks in string and bytecode search

## 👏 Acknowledgements

**All users** who helped improve the DeNuitkanizator project and contributed their time will be listed in ACKNOWLEDGEMENTS.md.

## ❗ Important

* **The project author (Mikhail / 2M12 / ThreatBit) is actively involved in development and reviews all PRs.**
* **All accepted Pull Requests will be included in the main repository with the author of the changes credited.**
* **Before starting major work, create an Issue — let’s discuss the architecture to avoid duplicate efforts.**

## 📩 Contacts

* GitHub: [@2M12](https://github.com/2M12)
* Zen: [ThreatBit](https://dzen.ru/threatbit)
