# DecryptCrypren
Decrypt Files Affected for Crypren Ransom

## Information of Sample:

| Name       | Hash           |
| ------------- |-------------:|
| MD5 | f6a8d7a4291c55020101d046371a8bda | 
| SHA1 | 09b08e04ee85b26ba5297cf3156653909671da90 |
| SHA256 | 082060e3320870d1d576083e0ee65c06a1104913ae866137f8ca45891c059a76 |

## Rule Yara
```yara
rule Ransom : Crypren{
	meta:
		weight = 1
		Author = "@pekeinfo"
		reference = ""
	strings: 
		$a = "won't be able to recover your files anymore.</p>"
		$b = {6A 03 68 ?? ?? ?? ?? B9 74 F1 AE 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 98 3A 00 00 FF D6 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ??}
		$c = "Please restart your computer and wait for instructions for decrypting your files"
	condition:
		any of them
}
```

## How To Get Key:
The key is a ascii imprimible. A example: lHMtMQHegfRomgQvLDpBVjNYpcTaIXKJ!3+8,$@*5?;.+3#+@@232.$#024085.6
* the first 32 char is a aphabetic
* the second 32 char is other char.
(i am working to script for get a key for one file)

### With Docx
Open some file, its prefer a word file, view this header and search 64 bytes repeat.
It more probable this is your key. Caution your first block not is the key.
example:

![Extraccion Key](https://raw.githubusercontent.com/pekeinfo/DecryptCrypren/master/src/HowToExtracKey.png "Extract key")

## Use Program
This program is only for one file. but i am working for multiple files.
### Compile
```Bash
gcc Solution.c -o Decrypt
```
### Execute
```Bash
Usage: ./Decrypt <filekey.txt> <file.Encrypted>
```

### Example
```
lab@lab-Infeccion:~/Documentos/DecryptCrypren$ ./Decrypt ransom/key.txt ransom/photo_2016-05-12_14-01-27.jpg.ENCRYPTED 
 File Key:ransom/key.txt	File encrypted:ransom/photo_2016-05-12_14-01-27.jpg.ENCRYPTED
 key is:lHMtMQHegfRomgQvLDpBVjNYpcTaIXKJ!3+8,$@*5?;.+3#+@@232.$#024085.6�Y��P
 -------------------------------------------------
 ransom/photo_2016-05-12_14-01-27.jpg.ENCRYPTED.decrypt
```
![Example](https://raw.githubusercontent.com/pekeinfo/DecryptCrypren/master/src/Example.png "Example")
