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