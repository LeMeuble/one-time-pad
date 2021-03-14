import os
import sys
import string
import base64
import secrets
import argparse
import subprocess

debug_mode = False


class KeyTooShort(Exception):
	pass


class InvalidKey(Exception):
	pass


class NotValidFormat(Exception):
	pass


class OneTimePad:

	alphabet = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11,
				'c': 12,
				'd': 13, 'e': 14, 'f': 15, 'g': 16, 'h': 17, 'i': 18, 'j': 19, 'k': 20, 'l': 21, 'm': 22, 'n': 23,
				'o': 24,
				'p': 25, 'q': 26, 'r': 27, 's': 28, 't': 29, 'u': 30, 'v': 31, 'w': 32, 'x': 33, 'y': 34, 'z': 35,
				'A': 36,
				'B': 37, 'C': 38, 'D': 39, 'E': 40, 'F': 41, 'G': 42, 'H': 43, 'I': 44, 'J': 45, 'K': 46, 'L': 47,
				'M': 48,
				'N': 49, 'O': 50, 'P': 51, 'Q': 52, 'R': 53, 'S': 54, 'T': 55, 'U': 56, 'V': 57, 'W': 58, 'X': 59,
				'Y': 60,
				'Z': 61, '!': 62, '"': 63, '#': 64, '$': 65, '%': 66, '&': 67, "'": 68, '(': 69, ')': 70, '*': 71,
				'+': 72,
				',': 73, '-': 74, '.': 75, '/': 76, ':': 77, ';': 78, '<': 79, '=': 80, '>': 81, '?': 82, '@': 83,
				'[': 84,
				'\\': 85, ']': 86, '^': 87, '_': 88, '`': 89, '{': 90, '|': 91, '}': 92, '~': 93, ' ': 94, '\t': 95,
				'\n': 96, '\r': 97}
	debug_mode = False
	no_errors = False

	def __init__(self, strength=32):
		self.strength = strength
		self.key = None
		self.text = None

	@staticmethod
	def generator(text_length, strength=32):
		"""Generates a random string

		:param text_length: The minimum length of the string generated
		:param strength: The maximum length to be added to the string (32 by default)
		:return: The key as a string
		"""

		length = int(strength)
		key = []
		number = secrets.randbelow(length)
		chars = string.ascii_letters + string.digits + string.punctuation

		for i in range(text_length + number):
			key.append(secrets.choice(chars))
		return "".join(key)

	def store_key(self, key_name="key.pem"):
		"""A function that stores the key into a file

		:param key_name: The name of the file to write the key (key.pem by default)
		:return: None
		"""

		if not key_name.endswith('.pem'):
			key_name += ".pem"

		if not isinstance(self.key, (str, bytes)):
			raise InvalidKey("The key is not a valid type, or may not be defined.")

		with open(key_name, "w") as file:
			file.write("-----BEGIN PRIVATE KEY-----")

			for i in range(0, len(self.key), 64):
				file.write(f"\n{self.key[i:i+64]}")

			file.write("\n-----END PRIVATE KEY-----")
			file.close()

	def open_key(self, key_file):
		"""A function that open the specified key file

		:param key_file: The name of the file to open
		:return: None
		"""
		if key_file.endswith(".pem"):
			with open(f"{key_file}") as file:
				key = file.readlines()

			i = 0
			self.key = ""

			for lines in key:

				if i == 0 or i == (len(key)-1):
					pass

				else:
					lines = lines.replace("\n", "")
					self.key += lines

				i += 1

		else:
			raise NotValidFormat("Selected file is not of a valid format (.pem)")

	def set_key(self, text):
		"""Set the key to encrypt text

		:param text: The text to encrypt, in order to define the key length
		:return: None
		"""

		global no_errors
		no_errors = args.no_errors

		self.key = ""
		input_key = ""

		# Generates a default key for text
		if args.key_length is not None:
			recommended = OneTimePad.generator(len(text), args.key_length)
		else:
			recommended = OneTimePad.generator(len(text))

		print(f"Recommended key : {recommended}")

		while len(input_key) < len(text) and len(self.key) < len(text):

			input_key = str(input(
				f"Enter a key (must be longer or equal to {len(text)}), type 'default' to use recommended key : "))

			if input_key == "default":
				self.key = recommended

			if len(input_key) < len(self.text) and input_key != "default" and not no_errors:
				raise KeyTooShort("Key is too short")

		if self.key == recommended:
			pass
		else:
			self.key = input_key

	def encrypt(self, text, key=None):
		"""Encrypt a piece of text

		:param text: The text to encrypt
		:param key: The key to encrypt the text with (None by default, has to be entered manually)
		:return: The cyphered text as a string
		"""

		global debug_mode, no_errors

		self.key = key
		self.text = text

		if self.key is None:
			OneTimePad.set_key(instance, text)

		self.text = list(text)
		self.key = list(self.key)

		if debug_mode:
			print(f"Text = {self.text}")
			print(f"Key = {key}")

		i = 0
		for letters in self.key:
			self.key[i] = (list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)])
			i += 1

		if debug_mode:
			print(f"Key index = {key}")

		i = 0
		for letters in self.text:
			self.text[i] = ((list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)]) +
							self.key[i]) % len(OneTimePad.alphabet)
			i += 1

		if debug_mode:
			print(f"Encrypted index = {text}")

		i = 0
		for letters in self.text:
			self.text[i] = (list(OneTimePad.alphabet.keys())[list(OneTimePad.alphabet.values()).index(letters)])
			i += 1

		return "".join(self.text)

	def decrypt(self, text, key=None):
		"""Decrypt a piece text

		:param text: The text to decrypt
		:param key: The key to encrypt the text with (None by default, has to be entered manually)
		:return: The deciphered text as a string
		"""

		global debug_mode, no_errors

		self.text = text
		self.key = key

		if self.key is None:
			self.key = str(input(f"Enter the key : "))

		if len(self.key) < len(self.text) and not no_errors:
			print("Key is too short to decrypt. If you want to run anyway, please use -no_errors")
			return

		self.text = list(self.text)
		self.key = list(self.key)

		if debug_mode:
			print(f"\nText = {self.text}")
			print(f"Key = {self.key}\n")

		i = 0
		for letters in self.key:
			self.key[i] = (list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)])
			i += 1

		if debug_mode:
			print(f"Key index = {self.key}")

		i = 0
		try:
			for letters in self.text:
				self.text[i] = ((list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)]) -
								self.key[i]) % len(OneTimePad.alphabet)
				i += 1

			if debug_mode:
				print(f"Decrypted index = {self.text}")

		except IndexError:
			print(f"Error, operation stopped at character {i}/{len(self.text)}")

			try:
				i = 0
				for letters in self.text:
					self.text[i] = (list(OneTimePad.alphabet.keys())[list(OneTimePad.alphabet.values()).index(letters)])
					i += 1
			except ValueError:

				separator = ""
				print(f"Partially decrypted text = {separator.join(self.text)}")

				return

		i = 0
		for letters in self.text:
			self.text[i] = (list(OneTimePad.alphabet.keys())[list(OneTimePad.alphabet.values()).index(letters)])
			i += 1

		return "".join(self.text)

	def encrypt_file(self, file):
		"""Encrypt a file

		:param file: The name of the file to encrypt
		:return: None
		"""

		global debug_mode, no_errors

		self.text = ""
		self.key = ""

		with open(file, "rb") as f:
			self.text = f.read()
			self.text = base64.b64encode(self.text)
			self.text = self.text.decode()
			f.close()

		OneTimePad.set_key(instance, self.text)

		with open(f"{file}_key.txt", "w") as f:
			f.write(self.key)
			f.close()

		self.text = list(self.text)
		self.key = list(self.key)

		if debug_mode:
			print(f"Text = {self.text}")
			print(f"Key = {self.key}")

		i = 0
		for letters in self.key:
			self.key[i] = (list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)])
			i += 1
		if debug_mode:
			print(f"Key index = {self.key}")

		i = 0
		for letters in self.text:
			self.text[i] = ((list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)]) +
							self.key[i]) % len(OneTimePad.alphabet)
			i += 1
		if debug_mode:
			print(f"Encrypted index = {self.text}")

		i = 0
		for letters in self.text:
			self.text[i] = (list(OneTimePad.alphabet.keys())[list(OneTimePad.alphabet.values()).index(letters)])
			i += 1

		separator = ""
		text = separator.join(self.text)
		if debug_mode:
			print(f"Encrypted text = {separator.join(self.text)}")

		print("\nThis will overwrite current file content and replace it with the encrypted one")
		choice = ""

		while choice.lower() not in ["yes", "no"]:

			choice = str(input(f"Are you sure you want to encrypt {file} ? (yes/no): "))

			if choice.lower() == "yes":
				with open(file, "wb") as f:
					f.write(base64.b64encode(text.encode()))
					f.close()
			if choice.lower() == "no":
				return

	def decrypt_file(self, file, key_file=None):
		"""Decrypt a file

		:param file: The file to decrypt
		:param key_file: The key to encrypt the file with (None by default, has to be entered manually)
		:return: None
		"""

		global debug_mode, no_errors

		self.key = ""
		self.text = ""

		with open(file, "rb") as f:
			self.text = f.read()
			try:
				self.text = base64.b64decode(self.text)
			except base64.binascii.Error:
				print(
					"Can't read the file. Make sure this file has been encrypted with base64/this software before trying to decrypt it.")
				return

			if debug_mode:
				print(self.text, type(self.text))
			f.close()
		print(self.text)
		if key_file is None:
			self.key = str(input("Enter the key : "))
		else:
			with open(key_file, "r") as f:
				self.key = f.read()
				f.close()

		self.text = list(self.text.decode())
		self.key = list(self.key)

		if debug_mode:
			print(f"Text = {self.text}")
			print(f"Key = {self.key}")

		i = 0
		for letters in self.key:
			self.key[i] = (list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)])
			i += 1
		if debug_mode:
			print(f"Key index = {self.key}")

		i = 0
		for letters in self.text:
			self.text[i] = ((list(OneTimePad.alphabet.values())[list(OneTimePad.alphabet.keys()).index(letters)]) -
							self.key[i]) % len(OneTimePad.alphabet)
			i += 1
		if debug_mode:
			print(f"Decrypted index = {self.text}")

		i = 0
		for letters in self.text:
			self.text[i] = (list(OneTimePad.alphabet.keys())[list(OneTimePad.alphabet.values()).index(letters)])
			i += 1
		separator = ""
		text = separator.join(self.text)
		if debug_mode:
			print(f"Encrypted text = {separator.join(text)}")

		print("\nThis will overwrite current file content and replace it with the decrypted one")
		choice = ""

		while choice.lower() not in ["yes", "no"]:

			choice = str(input(f"Are you sure you want to decrypt {file} ? (yes/no) : "))

			if choice.lower() == "yes":
				with open(file, "wb") as f:
					f.write(base64.b64decode(text.encode()))
					f.close()
			if choice.lower() == "no":
				return


instance = OneTimePad()
OneTimePad.open_key(instance, "my_key_file.pem")
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-encrypt", help="Encrypt a piece of text, for example -encrypt 'MyText")
	parser.add_argument("-decrypt", help="Decrypt a piece of text, for example -decrypt 'MySecretText")
	parser.add_argument("-encrypt_file", help="Encrypt the specified file")
	parser.add_argument("-decrypt_file", help="Decrypt the specified file")

	parser.add_argument("-key", help="Key to encrypt your text, for example -key 'MySecretKey'")
	parser.add_argument("-key_file", help="Key file to decrypt your file, for example -key 'MyFile.txt_key.txt'")
	parser.add_argument("-debug", help="Enable debug mode", action="store_true")
	parser.add_argument("-no_errors", help="Allow to run encryption/decryption with a key shorter than required",
						action="store_true")
	parser.add_argument("-key_length", help="Define the size of the random key")

	args = parser.parse_args()

	if args.debug:
		debug_mode = True

	if args.no_errors:
		no_errors = True

	if args.encrypt:
		if args.key:
			instance = OneTimePad()
			cyphered = OneTimePad.encrypt(instance, args.encrypt, args.key)
			print(f"Encrypted text = {cyphered}")
		else:
			instance = OneTimePad()
			cyphered = OneTimePad.encrypt(instance, args.encrypt)
			print(f"Encrypted text = {cyphered}")

	if args.decrypt:
		if args.key:

			instance = OneTimePad()
			deciphered = OneTimePad.decrypt(instance, args.decrypt, args.key)
			print(f"Decrypted text = {deciphered}")

		else:
			instance = OneTimePad()
			deciphered = OneTimePad.decrypt(instance, args.decrypt)
			print(f"Decrypted text = {deciphered}")

	if args.encrypt_file:
		instance = OneTimePad()
		OneTimePad.encrypt_file(instance, args.encrypt_file)

	if args.decrypt_file:
		if args.key_file:
			instance = OneTimePad()
			OneTimePad.decrypt_file(instance, args.decrypt_file, args.key_file)
		else:
			instance = OneTimePad()
			OneTimePad.decrypt_file(instance, args.decrypt_file)

# Todo : Beautify the code
# Todo : Store key into .pem formatted file
# Todo : Add function to open key file
# Todo : Add function that encrypt with XOR
