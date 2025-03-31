rule upx
{
  meta:
	  description = "Detect UPX-packed files"
	  author = "Daniel Roberson"
	  description = "https://github.com/upx/upx"

  strings:
	  $s1 = "UPX!"
	  $s2 = "UPX executable packer"

  condition:
      (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d) and all of them
}


rule elf_missing_sections
{
  meta:
      description = "ELF file with no section headers (likely packed)"
	  author = "Daniel Roberson"

  condition:
      uint32(0) == 0x464c457f and // ELF magic
      (
		  // 32 bit
	      (uint8(4) == 1 and uint32(0x20) == 0) or
		  // 64 bit
		  (uint8(4) == 2 and uint32(0x28) == 0 and uint32(0x2c) == 0)
	  )
}


rule upx_unpack_stub_linux_x86_64
{
  meta:
    description = "Detects extended UPX unpacking stub on Linux x86_64"
    author = "Daniel Roberson"

  strings:
    $stub = {
      54                // push rsp
      5F                // pop rdi
      51                // push rcx
      52                // push rdx
      31 C0             // xor eax,eax
      48 AF             // scasq
      75 FC             // jnz -4
      48 AF             // scasq
      75 FC             // jnz -4
      57                // push rdi
      BA 00 10 00 00    // mov edx, 0x1000
      5E                // pop rsi
      48 AD             // lodsq
      85 C0             // test eax, eax
      74 08             // jz skip
      83 F8 06          // cmp eax, 0x6
      48 AD             // lodsq
      75 F3             // jnz loop
      92                // xchg eax, edx
      58                // pop rax
      48 F7 DA          // neg rdx
      52                // push rdx
      50                // push rax
      68 ?? ?? ?? ??    // push "Xpu" (part of "upx")
      54                // push rsp
      5F                // pop rdi
      6A 10             // push 0x10
      5E                // pop rsi
      B8 3F 01 00 00    // mov eax, 0x13f (mmap syscall)
      0F 05             // syscall
    }

  condition:
    uint32(0) == 0x464c457f and $stub
}
