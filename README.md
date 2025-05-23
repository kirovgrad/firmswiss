# firmswiss

A tool to search through firmware filesystem directories for:

- Function origins
- Hex byte patterns
- Needed libraries
- Function substrings
- Assembly mnemonics

---

## Features

- **Find Origin**: Locate where a specific function is defined in firmware binaries.
- **Find Bytes**: Search for raw byte patterns (e.g., shellcode, magic numbers).
- **Find Needed**: Recursively extract needed shared libraries from binaries.
- **Find Subfunction**: Match functions by substring to infer relationships.
- **Find Mnemonics**: Detect binaries containing specific asm instructions.

---

## Usage

```bash
python firmswiss.py <fsdir> [OPTIONS]
```

### Arguments
* `fsdir`:Path to the extracted firmware filesystem.

### Options

* `-fo`, `--find_origin`	Find origin binary of function in firmware fs.
* `-fb`, `--find_bytes` 	Find specific bytes location in firmware fs binaries.
* `-fn`, `--find_needed` 	List required libraries of a binary recursively.
* `-fs`, `--find_subfunc`	Find functions by name substring.
* `-fm`, `--find_mnemonic`	Find specific assembler instructions location in fs binaries.


## Examples

```bash
# Find a function definition
python script.py ./firmware -fo base64_parser

# Search for a byte pattern
python script.py ./firmware -fb deadbeef

# List needed shared libraries of a binary
python script.py ./firmware -fn /bin/mybinary

# Find functions with 'init' in their name
python script.py ./firmware -fs init

# Search for asm instructions in all binaries
python script.py ./firmware -fm "i386:mov eax, 1;sub eax, 1;push eax"
```

## Requirements

- Python 3.6+
- `binascii`
- `argparse`
- `keystone`

Install dependencies:
```bash
pip install binascii argparse keystone
```

## 📁 Use Case

Useful for firmware reversing, vulnerability hunting, or custom static analysis.
