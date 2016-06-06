# DecryptCrypren

File decryption for those affected by the Crypren Ransomware.

## Sample Details

| Name       | Hash           |
| ------------- |-------------:|
| MD5 | f6a8d7a4291c55020101d046371a8bda | 
| SHA1 | 09b08e04ee85b26ba5297cf3156653909671da90 |
| SHA256 | 082060e3320870d1d576083e0ee65c06a1104913ae866137f8ca45891c059a76 |

## Yara Rule

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

## How To Get the Key

The key is an array of 64 ASCII printable chars, such as: `lHMtMQHegfRomgQvLDpBVjNYpcTaIXKJ!3+8,$@*5?;.+3#+@@232.$#024085.6`, matching the next conditions:

* The first 32 bytes are alphabetic ASCII chars
* The second 32 bytes are any possible ASCII char

### Decrypting Docx files

Open a Microsoft WORD file and locate the header section. The key may be revealed as a pattern of 64 bytes repeating across the file header.

Finding this pattern most likely means you have found your key, but be caution though and skip the first block, as this is not the key you're looking for.

Find below a key extraction example:

![Extraccion Key](https://github.com/mlwre/DecryptCrypren/blob/master/src/HowToExtracKey.png?raw=true"Extract key")

## Decryption Program

At the moment, the shared code decrypts the content for only one file, but the author is working on a version to support multiple files.

### Compilation
```Bash
gcc Solution.c -o Decrypt
```
### Execution
```Bash
Usage: ./Decrypt <filekey.txt> <file.Encrypted>
```
### Decryption Example
```
lab@lab-Infeccion:~/Documentos/DecryptCrypren$ ./Decrypt ransom/key.txt ransom/photo_2016-05-12_14-01-27.jpg.ENCRYPTED 
 File Key:ransom/key.txt	File encrypted:ransom/photo_2016-05-12_14-01-27.jpg.ENCRYPTED
 key is:lHMtMQHegfRomgQvLDpBVjNYpcTaIXKJ!3+8,$@*5?;.+3#+@@232.$#024085.6�Y��P
 -------------------------------------------------
 ransom/photo_2016-05-12_14-01-27.jpg.ENCRYPTED.decrypt
```
![Example](https://github.com/mlwre/DecryptCrypren/blob/master/src/Example.png?raw=true "Example")
