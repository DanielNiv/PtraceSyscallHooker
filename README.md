# PtraceSyscallHooker
Some fun and games with ptrace.

## Strace
Simple implementation of the strace util.

## secretWordDropper
Program that hooks the write syscall of the target proccess,
and checks if the word "TOP-SECRET" is in the buffer to be written.
If so, the syscall is dropped, and the buffer won't be written :)
Added a simple server that prints everything it receives.
If we run it, we can see that after we run the dropper with:

```bash
./dropper $(pidof server)
```

It wont print messages that contains "TOP-SECRET" in it.
