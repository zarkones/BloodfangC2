[BITS 32]

DEFAULT REL

EXTERN _entry
GLOBAL _bloodfang
GLOBAL _RipStart

[SECTION .text$A]
    _bloodfang:
        push ebp
        mov  ebp, esp
        call _entry
        mov  esp, ebp
        pop  ebp
    ret

    _RipStart:
        call _RipPtr
    ret

    _RipPtr:
        mov eax, [esp]
        sub eax, 0x11
    ret