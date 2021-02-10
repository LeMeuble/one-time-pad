import os
import sys
import string
import base64
import secrets
import subprocess

alphabet = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15, 'g': 16, 'h': 17, 'i': 18, 'j': 19, 'k': 20, 'l': 21, 'm': 22, 'n': 23, 'o': 24, 'p': 25, 'q': 26, 'r': 27, 's': 28, 't': 29, 'u': 30, 'v': 31, 'w': 32, 'x': 33, 'y': 34, 'z': 35, 'A': 36, 'B': 37, 'C': 38, 'D': 39, 'E': 40, 'F': 41, 'G': 42, 'H': 43, 'I': 44, 'J': 45, 'K': 46, 'L': 47, 'M': 48, 'N': 49, 'O': 50, 'P': 51, 'Q': 52, 'R': 53, 'S': 54, 'T': 55, 'U': 56, 'V': 57, 'W': 58, 'X': 59, 'Y': 60, 'Z': 61, '!': 62, '"': 63, '#': 64, '$': 65, '%': 66, '&': 67, "'": 68, '(': 69, ')': 70, '*': 71, '+': 72, ',': 73, '-': 74, '.': 75, '/': 76, ':': 77, ';': 78, '<': 79, '=': 80, '>': 81, '?': 82, '@': 83, '[': 84, '\\': 85, ']': 86, '^': 87, '_': 88, '`': 89, '{': 90, '|': 91, '}': 92, '~': 93, ' ': 94, '\t': 95, '\n': 96, '\r': 97}
debug_mode = False


def generator(text_length, length=32):
	key = []
	_separator = ""
	number = secrets.randbelow(length)
	_chars = string.ascii_letters + string.digits + string.punctuation

	for i in range(text_length+number):
		key.append(secrets.choice(_chars))
	return _separator.join(key)


def encrypt():
	global debug_mode

	key = ""

	text = str(input("Enter text to encrypt : "))
	while len(key) < len(text):
		print(f"Recommended key : {generator(len(text))}")
		key = str(input(f"Enter a key (must be longer or equal to {len(text)}) : "))

	text = list(text)
	key = list(key)
	print(f"Text = {text}")
	print(f"Key = {key}")

	i = 0
	for letters in key:
		key[i] = (list(alphabet.values())[list(alphabet.keys()).index(letters)])
		i += 1
	print(f"Key index = {key}")

	i = 0
	for letters in text:
		text[i] = ((list(alphabet.values())[list(alphabet.keys()).index(letters)]) + key[i]) % len(alphabet)
		i += 1

	print(f"Encrypted index = {text}")

	i = 0
	for letters in text:
		text[i] = (list(alphabet.keys())[list(alphabet.values()).index(letters)])
		i += 1
	separator = ""
	print(f"Encrypted text = {separator.join(text)}")


def decrypt():
	global debug_mode

	key = ""

	text = str(input("Enter text to decrypt : "))
	key = str(input(f"Enter the key : "))

	text = list(text)
	key = list(key)
	print(f"Text = {text}")
	print(f"Key = {key}")

	i = 0
	for letters in key:
		key[i] = (list(alphabet.values())[list(alphabet.keys()).index(letters)])
		i += 1
	print(f"Key index = {key}")

	i = 0
	for letters in text:
		text[i] = ((list(alphabet.values())[list(alphabet.keys()).index(letters)]) - key[i]) % len(alphabet)
		i += 1

	print(f"Encrypted index = {text}")

	i = 0
	for letters in text:
		text[i] = (list(alphabet.keys())[list(alphabet.values()).index(letters)])
		i += 1
	separator = ""
	print(f"Encrypted text = {separator.join(text)}")


def encrypt_file():

	global debug_mode
	key = ""

	file = input("Select file to encrypt : ")

	with open(file, "rb") as f:
		text = f.read()
		text = base64.b64encode(text)
		text = text.decode()
		f.close()

	while len(key) < len(text):
		recommanded = generator(len(text))
		print(f"Recommended key : {recommanded}")
		key = str(input(f"Enter a key (must be longer or equal to {len(text)}) : "))
		if key == "default":
			key = recommanded

	with open("key.txt", "a") as f:
		f.write(key + "\n" + "\n")
		f.close()

	text = list(text)
	key = list(key)
	if debug_mode:
		print(f"Text = {text}")
		print(f"Key = {key}")

	i = 0
	for letters in key:
		key[i] = (list(alphabet.values())[list(alphabet.keys()).index(letters)])
		i += 1
	if debug_mode:
		print(f"Key index = {key}")

	i = 0
	for letters in text:
		text[i] = ((list(alphabet.values())[list(alphabet.keys()).index(letters)]) + key[i]) % len(alphabet)
		i += 1
	if debug_mode:
		print(f"Encrypted index = {text}")

	i = 0
	for letters in text:
		text[i] = (list(alphabet.keys())[list(alphabet.values()).index(letters)])
		i += 1
	separator = ""
	text = separator.join(text)
	if debug_mode:
		print(f"Encrypted text = {separator.join(text)}")

	print("\nThis will overwrite current file content and replace it with the encrypted one")
	choice = None

	while choice not in ["yes", "no"]:

		choice = str(input(f"Are you sure you want to encrypt this file ? ({file}) : "))

		if choice.lower() == "yes":
			with open(file, "wb") as f:
				f.write(base64.b64encode(text.encode()))
				f.close()
		if choice.lower() == "no":
			sys.exit()


def decrypt_file():

	global debug_mode

	key = ""
	text = ""

	file = input("Select file to decrypt : ")
	with open(file, "rb") as f:
		text = f.read()
		text = base64.b64decode(text)
		text = text.decode()
		if debug_mode:
			print(text, type(text))
		f.close()

	key = str(input("Enter the key : "))
	print(f"Debug !!!! : {key}")

	text = list(text)
	key = list(key)
	print(f"Debug : {key}")
	if debug_mode:
		print(f"Text = {text}")
		print(f"Key = {key}")
	print(len(text), len(key))

	i = 0
	for letters in key:
		key[i] = (list(alphabet.values())[list(alphabet.keys()).index(letters)])
		i += 1
	if debug_mode:
		print(f"Key index = {key}")

	i = 0
	for letters in text:
		text[i] = ((list(alphabet.values())[list(alphabet.keys()).index(letters)]) - key[i]) % len(alphabet)
		i += 1
	if debug_mode:
		print(f"Encrypted index = {text}")

	i = 0
	for letters in text:
		text[i] = (list(alphabet.keys())[list(alphabet.values()).index(letters)])
		i += 1
	separator = ""
	text = separator.join(text)
	if debug_mode:
		print(f"Encrypted text = {separator.join(text)}")

	print("\nThis will overwrite current file content and replace it with the decrypted one")
	choice = None

	while choice not in ["yes", "no"]:

		choice = str(input(f"Are you sure you want to decrypt this file ? ({file}) : "))

		if choice.lower() == "yes":
			with open(file, "wb") as f:
				f.write(base64.b64decode(text.encode()))
				f.close()
		if choice.lower() == "no":
			sys.exit()


choice = None
print("0 : Exit")
print("encrypt : Encrypt text")
print("decrypt : Decrypt text")
print("encrypt_file : Encrypt file")
print("decrypt_file : Decrypt file")

while True:
	while choice not in ["exit", "encrypt", "decrypt", "encrypt_file", "decrypt_file", "clear"]:
		choice = str(input("> "))

	if choice == "exit":
		sys.exit()

	if choice == "encrypt":
		encrypt()

	if choice == "decrypt":
		decrypt()

	if choice == "encrypt_file":
		encrypt_file()

	if choice == "decrypt_file":
		decrypt_file()

	if choice == "clear":
		os.system("cls")

	print()
	choice = None

# Todo : Add settings with -> security level, debug mode
# Todo : Add commands ->  help
# Todo : Comment the code