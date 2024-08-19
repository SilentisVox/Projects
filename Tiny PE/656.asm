BITS 64

; DOS Header
    dw 'MZ'
    dw 0

; PE Header
pe_hdr:
    dw 'PE'
    dw 0
    dw 0x8664

code:

symbol:
    dw 0x01
    dq 0
    dd 0
    dw opt_hdr_size
    dw 0x22

opt_hdr:
    dw 0x020b
    dw 0
    dd code_size
    dq 0x00
    dd entry
    dd code
    dq 0x000140000000
    dd pe_hdr
    dd 0x04
    dq 0
    dw 0x06
    dw 0
    dd 0
    dd file_size
    dd hdr_size
    dd 0
    dw 0x02
    dw 0
    dq 0
    dq 0
    dq 0
    dq 0
    dd 0
    dd 0x02
    dq 0
    dq 0

opt_hdr_size equ $-opt_hdr
    dq 0
    dd sect_size
    dd 0
    dd code_size
    dd 0
    dq 0
    dq 0

hdr_size equ $-$$

entry:
    ret

sect_size equ $-code
code_size equ $-code
file_size equ $-$$
