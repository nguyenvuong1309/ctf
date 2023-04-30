![1](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/register.png)

- argv: argument passed to the function.
- argc: number of the argument.
- Return address: where the function should go next after done function.
- EBP: extended buffer pointer.
- ESP: extended stack pointer.
```
- sudo sysctl -w kernel.randomize_va_space=0
- compile 32 bit:  gcc 1.c -o 1.out -fno-stack-protector -m32
- sudo sysctl -p
- ulimit -c unlimited
- ulimit -c
```
```
INSTRUCTION IN IDA
- x64
```
![2](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/crackme01.png)
```
- endbr64 : This instruction is an "End Branch 64" (endbr64) instruction, which is a form of an instruction pointer integrity check used for control-flow integrity (CFI) enforcement.
- push rbx : This instruction pushes the value of the rbx register onto the stack. The rbx register is a general-purpose register in x86-64 architecture.
- cmp edi, 2 : This instruction performs a comparison between the value of the edi register (which likely contains a function argument) and the value 2. The result of the comparison will be used in the next instruction to determine whether to jump to a different location in the code.
- SI = Source Index.
- DI = Destination Index.
- jnz short loc_11B4 : This instruction jumps to the location labeled "loc_11B4" if the previous comparison did not result in a zero value. The "jnz" instruction means "jump if not zero", and the "short" keyword indicates that the jump is a relative jump within a small range.
- lea     rdi, aPassword1 : Load the address of the string "password1" into the rdi register.
- mov     rsi, rdx : Move the value in the rdx register into the rsi register.
- repe cmpsb : Compare the string in rdi with the string in rsi, up to the length of ecx, and repeat while they match.
- setnbe  bl  : Set bl to 1 if the last comparison result was not below or equal, otherwise set it to 0.
- sbb     bl, 0 : Subtract 0 from bl, setting the carry flag if bl is 0.
- movsx   ebx, bl : Move the signed value of bl into ebx (sign extension).
- test    ebx, ebx : Test whether ebx is zero (i.e. the strings matched).
- jnz      short loc_11C7 : Jump to the label loc_11C7 if the zero flag is set (i.e. the strings matched).
```
![3](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/crackme02.png)
```
- mov     rsi, [rsi+8]: 
 + The instruction "mov rsi, [rsi+8]" is an x86-64 assembly language instruction that loads a 64-bit value from memory into the RSI register.
 + The memory location from which the value is loaded is calculated by adding 8 to the current contents of the RSI register, and then treating the resulting value as a memory address.
 + In other words, this instruction is moving the value stored at memory location (RSI+8) into the RSI register.
 + The square brackets around "[rsi+8]" indicate that we are dereferencing a memory address. The contents of the memory address are being loaded into the RSI register, not the memory address itself.
 + In summary, the "mov rsi, [rsi+8]" instruction loads a 64-bit value from memory at the address (RSI+8) into the RSI register.
- movzx   edx, byte ptr [rsi+rcx] : 
 + The instruction "movzx edx, byte ptr [rsi+rcx]" is an x86 assembly language instruction that moves (copies) the value of a byte stored at a memory location into a 32-bit register, zero-extending it to 32 bits.
 + The "movzx" instruction stands for "move with zero extension," which means that it will fill the upper bits of the destination register (in this case, EDX) with zeros. This is useful when you want to sign-extend an unsigned byte to a larger data type.
 + The "byte ptr" keyword tells the assembler that we are referring to a byte-sized memory location. The memory address is calculated by adding the contents of the RCX register to the contents of the RSI register.
 + In summary, the instruction "movzx edx, byte ptr [rsi+rcx]" loads a byte-sized value from memory at the address (RSI+RCX) and then zero-extends that value to 32 bits, storing it in the EDX register.
- DL register : the lower 8 bits of the EDX register.
- movsx   eax, al :
 + The "movsx eax, al" instruction is an x86 assembly language instruction that moves a signed byte value from the AL register into the EAX register, sign-extending it to 32 bits.
 + The "movsx" instruction stands for "move with sign-extension," which means that it will fill the upper bits of the destination register (in this case, EAX) with a copy of the sign bit of the source operand (in this case, AL).
 + The AL register contains the lower 8 bits of the EAX register, which may represent a signed or unsigned value. The "movsx" instruction assumes that the value in AL is signed, and sign-extends it to 32 bits by copying the sign bit (the most significant bit) of AL into the upper 24 bits of EAX.
 + In summary, the "movsx eax, al" instruction moves a signed byte value from the AL register into the EAX register, sign-extending it to 32 bits. This can be useful when you need to convert a signed byte value into a 32-bit signed integer.
```
![3](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/crackme03.png)
```
- rdi: This register is typically used to pass the first function argument. It is also used to store the return value of a function that returns a single value in the rax register. For example, in the printf function, the format string is typically passed in rdi.
- rsi: This register is typically used to pass the second function argument. For example, in the printf function, the first data argument is typically passed in rsi.
- rdx: This register is typically used to pass the third function argument. For example, in the printf function, the second data argument is typically passed in rdx.
```
- __readfsqword : Read memory from a location specified by an offset relative to the beginning of the FS segment.
- strcspn : The C library function size_t strcspn(const char *str1, const char *str2) calculates the length of the initial segment of str1, which consists entirely of characters not in str2.
- Open image file in hex : `hexdump -C image.jpg`.
- Get info of break point in gdb: `info break`
- Delete break point in gdb : `del 3`
- Show assembly line in gdb : `show disassemble-next-line` -> `set disassemble-next-line on` -> `si`.
- Show assembly line in gdb : `display/i $pc`. 
- Show assembly line in gdb : `layout asm`. 
```
Hex -> decimal : int("0x12",16)
Hex -> binary : bin(int("0x12",16))[:2]
Binary -> decimal : int("100",2)
Binary -> hex : hex(int("100",2))
Decimal -> binary : bin(10)
Decimal -> hex : hexx(10)
```

- Display all registers in gdb: `info registers`.
- Print value of a register : `p $eax`.
- Print address of register : `info register ecx`.
- Print address of register : `x/x $eax`.   x/x
- Step one instruction in gdb : `stepi`.
- This is a dynamically-linked, position-independent (PIE) binary. `set stop-on-solib-events 1` [how-to-set-earliest-possible-breakpoint](https://stackoverflow.com/questions/22488499/how-to-set-earliest-possible-breakpoint)
- radare2 : `r2 -d ./layers`
- V : switch to hex view.(press p to switch to anather view)
- v : switch to text view.
- f8 : jump into.
- f7 : move out.
 
# picoctf
- [bbbbloat](https://play.picoctf.org/practice/challenge/255?page=1&search=bb)
![1](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/bbbbloat1.png)
![1](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/bbbbloat2.png)
![1](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/bbbbloat3.png)

- push    rbp             ; Push the current base pointer onto the stack
- mov     rbp, rsp        ; Set the base pointer to the current stack pointer
- sub     rsp, 50h        ; Allocate 80 bytes of space on the stack for local variables
- mov     [rbp+var_44], edi  ; Store the value of the EDI register in the local variable at RBP-0x44
- mov     [rbp+var_50], rsi  ; Store the value of the RSI register in the local variable at RBP-0x50
- mov     rax, fs:28h     ; Load the value of the FS segment register plus 0x28 into the RAX register
- mov     [rbp+var_8], rax   ; Store the value of RAX in the local variable at RBP-0x8
- xor     eax, eax        ; Set the EAX register to zero
- mov     rax, 4C75257240343A41h ; Load a 64-bit constant into RAX
- mov     rdx, 3062396630664634h ; Load another 64-bit constant into RDX
- mov     [rbp+var_30], rax   ; Store the value of RAX in the local variable at RBP-0x30
- mov     [rbp+var_28], rdx   ; Store the value of RDX in the local variable at RBP-0x28
- mov     rax, 65623066635F3D33h ; Load a 64-bit constant into RAX
- mov     rdx, 4E326560623535h   ; Load another 64-bit constant into RDX
- mov     [rbp+var_20], rax   ; Store the value of RAX in the local variable at RBP-0x20
- mov     [rbp+var_18], rdx   ; Store the value of RDX in the local variable at RBP-0x18
- mov     [rbp+var_3C], 3078h ; Store the value 0x3078 in the local variable at RBP-0x3C
- add     [rbp+var_3C], 13C29Eh ; Add 0x13C29E to the value in the local variable at RBP-0x3C
- sub     [rbp+var_3C], 30A8h ; Subtract 0x30A8 from the value in the local variable at RBP-0x3C
- shl     [rbp+var_3C], 1   ; Shift the value in the local variable at RBP-0x3C left by one bit
- mov     eax, [rbp+var_3C] ; Move the value of the local variable at RBP-0x3C into the EAX register
- movsxd rdx, eax: Sign-extend eax to 64 bits and store the result in rdx.
- imul rdx, 55555556h: Multiply the value in rdx by 0x55555556 and store the result in rdx. This multiplication is equivalent to dividing by 3, using some bit tricks.
- shr rdx, 20h: Shift the value in rdx to the right by 32 - 20 = 12 bits.
- sar eax, 1Fh: Shift the value in eax to the right by 31 bits, filling the leftmost bits with the sign bit (i.e., 0 for positive values, 1 for negative values).
- mov ecx, edx: Move the value in edx to ecx.
- sub ecx, eax: Subtract the value in eax from ecx and store the result in eax.
- mov eax, ecx: Move the value in ecx to eax. At this point, eax contains a random-looking integer value that depends on the initial value of eax.
- mov [rbp+var_3C], eax: Store the value in eax in the local variable at [rbp+var_3C].
- mov [rbp+var_3C], 3078h: Set the value of the local variable at [rbp+var_3C] to 0x3078.
- add [rbp+var_3C], 13C29Eh: Add 0x13C29E to the value of the local variable at [rbp+var_3C].
- sub [rbp+var_3C], 30A8h: Subtract 0x30A8 from the value of the local variable at [rbp+var_3C].
- shl [rbp+var_3C], 1: Shift the value of the local variable at [rbp+var_3C] to the left by 1 bit.
- mov eax, [rbp+var_3C]: Move the value of the local variable at [rbp+var_3C] to eax.
- movsxd rdx, eax: Sign-extend eax to 64 bits and store the result in rdx.
- imul rdx, 55555556h: Multiply the value in rdx by 0x55555556 and store the result in rdx. This multiplication is equivalent to dividing by 3, using some bit tricks.
- shr rdx, 20h: Shift the value in rdx to the right by 32 - 20 = 12 bits.
- sar eax, 1Fh: Shift the value in eax to the right by 31 bits, filling the leftmost bits with the sign bit (i.e., 0 for positive values, 1 for negative values).
- mov ecx, edx: Move the value in edx to ecx.
- sub ecx, eax: Subtract the value in eax from ecx and store the result in eax.
- mov eax, ecx: Move the value in ecx.
- lea     rdi, aD         ; Load the format string "%d" into the RDI register
- mov     eax, 0         ; Move the value 0 into the EAX register
- call    ___isoc99_scanf ; Call the scanf function to read integer input from the user

- mov     [rbp+var_3C], 3078h  ; Move the value 0x3078 (12312 in decimal) into the variable at RBP - 0x3C
- add     [rbp+var_3C], 13C29Eh ; Add 0x13C29E (1256318 in decimal) to the variable at RBP - 0x3C
- sub     [rbp+var_3C], 30A8h   ; Subtract 0x30A8 (12456 in decimal) from the variable at RBP - 0x3C
- shl     [rbp+var_3C], 1      ; Shift the variable at RBP - 0x3C left by 1 bit
- mov     eax, [rbp+var_3C]    ; Move the value of the variable at RBP - 0x3C into the EAX register
- movsxd  rdx, eax             ; Move the signed doubleword value of EAX into RDX
- imul    rdx, 55555556h       ; Multiply RDX by 0x55555556 (1431655766 in decimal)
- shr     rdx, 20h             ; Shift the value of RDX right by 32 bits
- sar     eax, 1Fh             ; Shift the value of EAX right by 31 bits, filling the leftmost bits with 1's
- mov     esi, edx             ; Move the value of RDX into the ESI register
- sub     esi, eax             ; Subtract the value of EAX from ESI
- mov     eax, esi             ; Move the value of ESI into EAX
- mov     [rbp+var_3C], eax  ; Move the value of EAX register into the memory location at RBP-0x3C
- mov     [rbp+var_3C], 3078h  ; Move the value 0x3078 into the memory location at RBP-0x3C
- add     [rbp+var_3C], 13C29Eh  ; Add 0x13C29E to the value at the memory location RBP-0x3C
- sub     [rbp+var_3C], 30A8h  ; Subtract 0x30A8 from the value at the memory location RBP-0x3C
- shl     [rbp+var_3C], 1  ; Bitwise left shift the value at the memory location RBP-0x3C by 1 bit
- mov     eax, [rbp+var_3C]  ; Move the value at the memory location RBP-0x3C into the EAX register
- movsxd  rdx, eax  ; Sign-extend EAX into RDX
- imul    rdx, 55555556h  ; Multiply RDX by 0x55555556
- shr     rdx, 20h  ; Bitwise right shift RDX by 0x20 bits
- sar     eax, 1Fh  ; Arithmetic right shift EAX by 0x1F bits
- mov     edi, edx  ; Move the value in RDX into the EDI register
- sub     edi, eax  ; Subtract the value in EAX from the value in EDI and store the result in EDI
- mov     eax, edi  ; Move the value in EDI into the EAX register
- mov     [rbp+var_3C], eax  ; Move the value in EAX into the memory location RBP-0x3C
- mov     eax, [rbp+var_40]  ; Move the value at the memory location RBP-0x40 into the EAX register
- cmp     eax, 86187h  ; Compare the value in EAX with the value 0x86187
- jnz     loc_1583  ; Jump to the location labeled "loc_1583" if the values are not equal

![1](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/bbbbloat4.png)

- mov     [rbp+var_3C], 3078h  ; move the value 0x3078 into the memory location [rbp-0x3C]
- add     [rbp+var_3C], 13C29Eh ; add the value 0x13C29E to the memory location [rbp-0x3C]
- sub     [rbp+var_3C], 30A8h   ; subtract the value 0x30A8 from the memory location [rbp-0x3C]
- shl     [rbp+var_3C], 1      ; shift the value in [rbp-0x3C] left by one bit

- mov     eax, [rbp+var_3C]    ; move the value in [rbp-0x3C] into the eax register
- movsxd  rdx, eax             ; sign-extend the value in eax into the rdx register
- imul    rdx, 55555556h       ; multiply the value in rdx by 0x55555556
- shr     rdx, 20h             ; shift the value in rdx right by 0x20 bits
- sar     eax, 1Fh             ; shift the value in eax right by 0x1F bits with sign extension
- mov     ecx, edx             ; move the value in edx into the ecx register
- sub     ecx, eax             ; subtract the value in eax from the value in ecx and store the result in ecx
- mov     eax, ecx             ; move the value in ecx into the eax register
- mov     [rbp+var_3C], eax    ; move the value in eax into the memory location [rbp-0x3C]
 
- mov     [rbp+var_3C], 3078h  ; move the value 0x3078 into the memory location [rbp-0x3C]
- add     [rbp+var_3C], 13C29Eh ; add the value 0x13C29E to the memory location [rbp-0x3C]
- sub     [rbp+var_3C], 30A8h   ; subtract the value 0x30A8 from the memory location [rbp-0x3C]
- shl     [rbp+var_3C], 1      ; shift the value in [rbp-0x3C] left by one bit
 
- mov     eax, [rbp+var_3C] ; move the value at [rbp-0x3C] into eax
- movsxd  rdx, eax         ; sign-extend the value in eax into rdx
- imul    rdx, 55555556h   ; multiply the value in rdx by 0x55555556
- shr     rdx, 20h         ; shift the value in rdx right by 0x20 bits
- sar     eax, 1Fh         ; shift the value in eax right by 0x1F bits with sign extension
- mov     esi, edx         ; move the value in edx into esi
- sub     esi, eax         ; subtract the value in eax from the value in esi and store the result in esi
- mov     eax, esi         ; move the value in esi into eax
- mov     [rbp+var_3C], eax ; move the value in eax into [rbp-0x3C]
 
- lea     rax, [rbp+var_30] ; compute the address of [rbp-0x30] and store it in rax
- mov     rsi, rax         ; move the value in rax into rsi
- mov     edi, 0           ; move the value 0 into edi
- call    near ptr sub_1248+1 ; call the function sub_1248+1 with arguments rdi=0 and rsi=rbp-0x30, and store the return value in rax
- mov     [rbp+s], rax     ; move the return value from rax into the memory location [rbp-s]
 
- mov     rdx, cs:stdout   ; move the value of stdout into rdx
- mov     rax, [rbp+s]     ; move the value at [rbp-s] into rax
- mov     rsi, rdx         ; move the value in rdx into rsi (stream argument)
- mov     rdi, rax         ; move the value in rax into rdi (string argument)
- call    _fputs           ; call the fputs function with arguments rdi=string and rsi=stream
 
- mov     edi, 0Ah         ; move the value of '\n' into edi (newline character)
- call    _putchar         ; call the putchar function with argument edi='\n'
 
- mov     rax, [rbp+s]     ; move the value at [rbp-s] into rax
- mov     rdi, rax         ; move the value in rax into rdi (pointer argument for free)
- call    _free            ; call the free function with argument rdi=pointer
 
- jmp     short loc_158F   ; jump to the instruction at label loc_158F
 