from pwn import *
context.log_level = "debug"

HOST = "localhost"
#HOST = ""
PORT = 4444
#PORT = 

s = remote(HOST, PORT)

elf = ELF("./elf_name")
#libc = ELF("./libc_name")
pause()

s.interactive()