Decrypt or encrypt GTA IV files or retrieve GTA IV encryption keys.

## Usage

```
./gta4-decrypt <option> <.exe> <offset> {infile} {outfile}
```

options:

`<-k> <.exe> <off>`: Retrieve the key from the executable `<.exe>` at the file offset `<off>`.

`<-d> <.exe> <off> <infile> <outfile>`: Decrypt the file `<infile>` and save the decrypted file in `<outfile>`.

`<-e> <.exe> <off> <infile> <outfile>`: Encrypt the file `<infile>` and save the encrypted file in `<outfile>`.

## File offsets

Retrieve the file offset from: https://gtamods.com/wiki/Cryptography#Key

The newest game version on Steam is 1.2.0.59.

## Compatibility

All GTA IV game versions.

## Building

```
$ make
```
