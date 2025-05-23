# Dynamic Code Loading: Runtime Assembling

Welcome to my first blog post! I wanted to kick things off with something unique that I haven’t seen many people discuss: **Dynamic code loading**. More specifically, we’ll explore how to assemble code at runtime, map it into memory, and execute it dynamically in C, which is useful for things like polymorphic engines. This technique enables you to modify code before it’s mapped, control memory allocation, and keep certain code away from static analysis by EDR's/antiviruses.

In this post, we’ll assemble an x86-64 subroutine at runtime using the [Keystone Assembler](https://github.com/keystone-engine/keystone) and then map it into memory to call it directly. In our example, we’ll create a function that checks for debuggers — but we’re assembling it in memory at runtime, so no function declaration is necessary in the code itself.

## Requirements
To follow along, you’ll need:
- **Keystone Assembler**: Install it [here](https://github.com/keystone-engine/keystone).
- Knowledge of **C programming** and **memory management**.
- Good knowledge in both **assembly** and **systems programming on Linux**.

## The Code
Below is the code that assembles a subroutine to detect debuggers, maps it into memory, and then calls it.

```C
#include <sys/mman.h>
#include <keystone/keystone.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * x86-64 assembly code for a subroutine that will return 1
 * if a debugger is detected otherwise 0, this is a very well
 * known and basic way to detect debuggers on linux,
 * soon I will cover some more advanced techniques
 */
static char sub_detect_debugger_asm[] =
"push rbp\n"
"mov rbp, rsp\n"
"push rdi\n"
"push rsi\n"
"mov eax, 101\n"
"xor edi, edi\n"
"xor esi, esi\n"
"syscall\n"
"test eax, eax\n"
"setne al\n"
"movzx eax, al\n"
"pop rsi\n"
"pop rdi\n"
"leave\n"
"ret\n"
;

int main()
{

    /* use the lovely keystone assembler to assemble our code */
    ks_engine *ks;
    unsigned char *machine_code;
    size_t machine_code_size, count;

    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
        perror("ks_open");
        return EXIT_FAILURE;
    }

    if (ks_asm(ks, sub_detect_debugger_asm, 0, &machine_code, &machine_code_size, &count) != KS_ERR_OK) {
        perror("ks_asm");
        ks_close(ks);
        return EXIT_FAILURE;
    }
    ks_close(ks);

    /* map in a memory region to relocate the machine code into, pass NULL into rdi so the kernel chooses the address  */
    void *subroutine = mmap(NULL, machine_code_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (subroutine == MAP_FAILED) {
        perror("mmap");
        ks_free(machine_code);
        return EXIT_FAILURE;
    }

    /* copy the machine code for the subroutine into the memory region */
    memcpy(subroutine, machine_code, machine_code_size);
    ks_free(machine_code);

    /* change permissions for the memory region to RX so we can call it */
    if (mprotect(subroutine, machine_code_size, PROT_READ | PROT_EXEC) < 0) {
        perror("mprotect");
        munmap(subroutine, machine_code_size);
        return EXIT_FAILURE;
    }

    /* call the subroutine */
    int detected_debugger;
    __asm__ __volatile__ (
    "call *%1;"
    "mov %%eax, %0;"
    :"=r"(detected_debugger)
    :"r"(subroutine)
    :"%eax"
    );

    printf("debugged: %d\n", detected_debugger);

    /* unmap the memory address */
    munmap(subroutine, machine_code_size);
    return EXIT_SUCCESS;
}
```

*remember to compile it with -lkeystone*

## Explanation of Each Step

**Assembly Code String**: sub_detect_debugger_asm contains x86-64 assembly code for a subroutine which will detect a debugger. If detected, it returns 1; otherwise, it returns 0. 

**Assembling**: We use ks_asm to assemble the code string into machine code. 

**Memory Mapping**: mmap is called to allocate a readable and writable memory region for the assembled code. 

**Memory Relocation**: We use memcpy to copy the machine code into our allocated memory, then we free the machine code generated by ks_asm with ks_free.

**Changing Memory Permissions**: We use mprotect to change the region’s permissions from writeable to executable. 

**Execution**: By calling the start address of the memory region, the assembled code is called as a subroutine, and the result (1 or 0) is then printed. 

**Cleanup**: We call munmap to unmap the region of memory containing the subroutine. 

# Result
When you run this code, it prints 'debugged: 0' if no debugger is attached, or 'debugged: 1' if one is. \
**Here’s an example of it running with and without a debugger attached**:

Without Debugger:

![advanced_dynamic_code_loading_1_1](https://github.com/user-attachments/assets/76f1565b-1f35-43c6-b4bc-49e09c5d4e6e)

debugged: 0

With Debugger:

![advanced_dynamic_code_loading_1_2](https://github.com/user-attachments/assets/cfae4262-a647-414c-94ce-fbb22c5b7a6b)

debugged: 1

# Why This Matters

This technique of runtime assembling and mapping is significant, especially for polymorphic engines because it allows code to be modified and relocated dynamically. By mapping code into memory at runtime, we’re also keeping it away from static analysis by EDR's/antiviruses, making it harder for detection during scans. 

For more complex use cases, you can generate custom assembly code for each run or modify the code to adapt to different environments or even encrypt the assembly then decrypt it at runtime with a unique key for each build, making this technique very adaptable and useable in many different scenarios.

Stay tuned for more posts where I’ll dive deeper into more advanced malware development techniques.

If you have any questions then feel free to reach out to me on Discord: **serpentsobased**
