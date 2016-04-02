#ifndef ELF_UTILS_H_
#define ELF_UTILS_H_
#include <stdio.h>
#include <elf.h>

FILE* OpenElfFile(const char* library_path);
void CloseElfFile(FILE* elf_file);
void GetElfHeader(Elf32_Ehdr* elf_header, FILE* elf_file);
size_t GetShstrtabContent(char** shstrtab_content, FILE* elf_file);
void GetSectionHeaderByName(Elf32_Shdr* section_header, FILE* elf_file, const char* target_section_name);
void PatchRemoteGot(pid_t pid, const char* library_path, long original_function_addr, long target_function_addr);
#endif
