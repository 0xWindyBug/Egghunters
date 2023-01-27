# SEH Based Egghunter
Windows SEH based egghunter for overcoming space restrictions - Searching for "w00tw00t"
(registers it's own exception handler to handle access violations when iterating throguh the process's Virtual Address Space.

Methodology:
1. perform jmp to the handler's implementation block
2. handler's block starts with call to the "register _EXCEPTION_REGISTRATION_RECORD" block, pushing eip, and therefore the actual address of the handler onto the stack
3. in order to register the ERR -> pop adress from the stack and push along the next attribute(0xffffffff) to the stack, overwrite fs:0(exception_list) with esp.
4. before iterating through the VAS, overwrite StackBase(fs:4) with the handler's address -0x06 (Dispatch Exception performs 4 main checks on our ERR, one being a validation that the handler's code sits above the stackbase , we'd like to place our egghunter on the stack sometimes, so we have to fake the stackbase :)
5. we iterate through the vas looking for "w00tw00t" egg which will prepend the shellcode wherever its being placed , in case of an access violation handler will be executed
6. the handler performs two main things -> overwrite esp + 0x0c(CONTEXT struct, passed to _Except_Handler as 3rd param) at offset 0x06(eip member) with the address of inc page block , and return 0 in eax for _EXCEPTION_DISPOSITION continue execution which will restore execution at CONTEXT's eip member
