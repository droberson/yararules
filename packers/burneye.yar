rule burneye
{
  meta:
	  description = "burneye ELF encrypter"

  strings:
	  $ = "TEEE burneye - TESO ELF Encryption Engine"

  condition:
	  uint32(0) == 0x464c457f and all of them

}
