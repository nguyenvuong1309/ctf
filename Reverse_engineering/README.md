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
![3](https://github.com/SieuPhongDo/ctf/blob/main/Reverse_engineering/register.png)
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
