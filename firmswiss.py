import os
import binascii
import argparse
import threading
import subprocess
from keystone import *
from concurrent.futures import ThreadPoolExecutor


class NeededLibrarySearcher:
	def __init__(self, binary_path, directory, max_workers=10):
		self.target_binary = binary_path
		self.directory = os.path.abspath(directory)
		self.max_workers = max_workers
		self.lock = threading.Lock()


class OriginFunctionSearcher:
	def __init__(self, function_name, directory, whole_name=True, max_workers=10):
		self.function_name = function_name
		self.directory = os.path.abspath(directory)
		self.whole_name = whole_name
		self.results = {}
		self.max_workers = max_workers
		self.lock = threading.Lock()

	def search_in_file(self, filepath):
		try:
			with open(filepath, "rb") as f:
				if f.read(4) != b"\x7fELF":
					return False
		except (IOError, OSError):
			return False

		try:
			result = subprocess.run(["objdump", "-T", filepath], capture_output=True, text=True)
			for line in result.stdout.splitlines():
				if ".text" not in line:
					continue
				parts = line.split()
				func_name = parts[-1]
				if (self.whole_name and func_name == self.function_name) or \
				   (not self.whole_name and self.function_name in func_name):
					self.results[filepath] = parts
					break
		except (IOError, OSError) as e:
			with self.lock:
				print(f"Error occurred: {e}.")

	def find_elf_files(self):
		with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
			for root, _, files in os.walk(self.directory):
				for filename in files:
					filepath = os.path.join(root, filename)
					executor.submit(self.search_in_file, filepath)

	def print_results(self):
		if not self.results:
			print("No matches found.")
			return

		print(f"\n  {'Function':<40}{'File':<30}{'Offset':<10}{'Size':<10}")
		print("-" * 90)

		for filepath, results in self.results.items():
			relative_path = os.path.relpath(filepath, self.directory)
			func_offset = results[0]
			func_size = results[4]
			func_name = results[-1]

			print(f"  {func_name:<40}{relative_path:<30}{func_offset:<10}{func_size:<10}")

	def run(self):
		print(f"\n  Searching for {self.function_name}...")
		self.find_elf_files()
		self.print_results()


class HexSearcher:
	def __init__(self, hex_bytes, directory, opcode=False, max_workers=10):
		if not opcode:
			self.hex_bytes = hex_bytes.replace("0x", "").replace(" ", "")
			try:
				self.search_bytes = binascii.unhexlify(self.hex_bytes)
			except binascii.Error:
				raise ValueError("Invalid hex string provided")
		else:
			self.hex_bytes = self.convert_to_opcode(hex_bytes)
			self.search_bytes = binascii.unhexlify(self.hex_bytes)

		self.directory = os.path.abspath(directory)
		self.max_workers = max_workers
		self.results = []
		self.lock = threading.Lock()

	def convert_to_opcode(self, mnemonics):
		try:
			arch, inst = map(str.strip, mnemonics.split(":", 1))
		except ValueError:
			raise ValueError("Invalid command. Use 'arch:mnemonics', e.g., 'i386:mov eax,1; push eax'.")

		keystone_map = {
			"i386":   (KS_ARCH_X86, KS_MODE_32),
			"x8664":  (KS_ARCH_X86, KS_MODE_64),
			"arm32":  (KS_ARCH_ARM, KS_MODE_ARM),
			"arm64":  (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
		}

		if arch not in keystone_map:
			raise ValueError("Unsupported arch. Use: i386, x8664, arm32, arm64")

		try:
			ks = Ks(*keystone_map[arch])
			encoding, _ = ks.asm(inst.replace("#", ""))
			return bytes(encoding).hex()
		except KsError as e:
			raise ValueError(f"Assembly error: {e}")

	def search_in_file(self, filepath):
		try:
			with open(filepath, "rb") as f:
				if f.read(4) != b"\x7fELF":
					return False
		except (IOError, OSError):
			return False

		try:
			with open(filepath, "rb") as f:
				content = f.read()
				offset = 0
				while True:
					pos = content.find(self.search_bytes, offset)
					if pos == -1:
						break
					with self.lock:
						self.results.append((filepath, pos))
					offset = pos + 1
		except (IOError, OSError) as e:
			with self.lock:
				self.results.append((filepath, f"Error: {str(e)}"))

	def find_elf_files(self):
		with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
			for root, _, files in os.walk(self.directory):
				for filename in files:
					filepath = os.path.join(root, filename)
					executor.submit(self.search_in_file, filepath)

	def print_results(self):
		if not self.results:
			print("No matches found.")
			return

		print(f"\nSearch results for bytes: {self.hex_bytes}")
		print("=" * 50)

		# Group results by file
		file_results = {}
		for filepath, result in sorted(self.results):
			if isinstance(result, int):
				file_results.setdefault(filepath, []).append(result)
			else:
				file_results[filepath] = result

		for filepath, results in file_results.items():
			relative_path = os.path.relpath(filepath, self.directory)
			print(f"\n  File: {relative_path}")
			print("-" * 40)

			if isinstance(results, str):
				print(f"  {results}")
			else:
				for offset in results[:5]:
					print(f"  Found at offset: 0x{offset:x} ({offset} decimal)")
				if len(results) > 5:
					print(f"  And {len(results)-5} other offsets was found.")
		print("=" * 50)

	def run(self):
		print(f"\nSearching for {self.hex_bytes} in {self.directory}...")
		self.find_elf_files()
		self.print_results()


def main(fsdir, **kwargs):
	searchers = {
		"find_origin": lambda val: OriginFunctionSearcher(val, fsdir),
		"find_bytes": lambda val: HexSearcher(val, fsdir),
		"find_needed": lambda val: NeededLibrarySearcher(val, fsdir),
		"find_subfunc": lambda val: OriginFunctionSearcher(val, fsdir, whole_name=False),
		"find_mnemonic": lambda val: HexSearcher(val, fsdir, opcode=True),
	}

	for key, constructor in searchers.items():
		val = kwargs.get(key)
		if val:
			constructor(val).run()
			break


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(
		description="Swiss tool for managing firmware files",
		epilog="""
Examples:
  Find origin binary of a function:
	script.py /path/to/fs -fo function_name

  Find specific byte pattern:
	script.py /path/to/fs -fb deadbeef

  Find needed libraries:
	script.py /path/to/fs -fn binary_name

  Find functions by substring:
	script.py /path/to/fs -fs substring

  Find specific asm mnemonic location:
  Specify arch before comma: i386, x8664, arm32, arm64:
	script.py /path/to/fs -fm 'i386:mov eax, 1;sub eax, 10;push eax'
""",
	formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("fsdir", type=str, help="Firmware filesystem directory path to search in.")
	parser.add_argument("-fo", "--find_origin", type=str, help="Find origin binary of the function in firmware fs.")
	parser.add_argument("-fb", "--find_bytes", type=str, help="Find specific bytes in firmware fs binaries.")
	parser.add_argument("-fn", "--find_needed", type=str, help="Find needed libraries of binary recursively.")
	parser.add_argument("-fs", "--find_subfunc", type=str, help="Find function names in binaries by common substring.")
	parser.add_argument("-fm", "--find_mnemonic", type=str, help="Find specific asm instruction location in binaries.")

	args = parser.parse_args()
	main(args.fsdir,
		 find_origin=args.find_origin,
		 find_bytes=args.find_bytes,
		 find_needed=args.find_needed,
		 find_subfunc=args.find_subfunc,
		 find_mnemonic=args.find_mnemonic)
