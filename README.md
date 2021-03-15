# one-time-pad

A python script to encrypt text or files.

## Arguments

Use `-encrypt` to encrypt a piece of text.

Use `-decrypt` to decrypt the piece of text.

Use `-encrypt_file` to encrypt a file.

Use `-decrypt_file` to decrypt a file.

## Optionals arguments

Use `-key` to specify the key to encrypt or decrypt your data. When working with files, specially larger ones, prefer to use `-key_file`

Use `-key_file` to specify the name of the file containing the key to decrypt your data 

Use `-debug` to enable debug mode, displaying the status of the key and the data at different moments of their processing. Not yet fully beautified.

Use `-no_errors` to allow the cyphering / deciphering with a key shorter than the data.

Use `-key_length` to define the additional size of the random key.

## Usage

* From command line :  

     `python main.py -encrypt "Hello there !"`
        
     `python main.py -decrypt "" -key ""`
     
     `python main.py -decrypt "" -key "" -no_errors`

* By importing it in a file:

```python 

```

    
## Warning 
This is still WIP, and poorly developed, so I definitely would not recommend you using it on important data.
I will not take the responsability in case of loss of data.


## Licence 
[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)