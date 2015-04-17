global _start

section .text

_start:
    jmp MESSAGE      ; 1) lets jump to MESSAGE


ERROR:				; handling the write sys call error.
	mov eax,4            	; The system call for write (sys_write)
	mov ebx,1            	; File descriptor 1 - standard output
	mov ecx,error        	; Put the offset of hello in ecx
	mov edx,len_err	     	; Length of the message
	int 0x80              	; Call the kernel

	mov eax,1            	; The system call for exit (sys_exit)
	mov ebx,0            	; Exit with return code of 0 (no error)
	int 0x80


GOBACK:
    mov eax, 0x4
    mov ebx, 0x1
    pop ecx          ; 3) we are poping into `ecx`, now we have the
                     ; address of "Hello, World!\r\n" 
    mov edx, 0xF
    int 0x80

    ;mov eax,-1			;uncomment this line to see jumping of the label
    bt eax,63			;checking the 64th bit in eax register to be signed or not. -ve means error flag.
    jc ERROR			;jump if MSB is set
    int 0x80
    

    mov eax, 0x1	;preparing for exit.
    mov ebx, 0x0
    int 0x80


MESSAGE:
    call GOBACK       ; 2) we are going back, since we used `call`, that means
                      ; the return address, which is in this case the address 
                      ; of "Hello, World!\r\n", is pushed into the stack.
    
    db "Hello World!", 0dh, 0ah

section .data

	error:     db 'Error Occured. Exiting program now.',10    	
	len_err:   equ $-error
	
	



