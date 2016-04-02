#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include "config.h"
#include "elf_utils.h"
#include "ptrace.h"
#include "utils.h"

FILE* OpenElfFile(const char* library_path) {
  if (library_path != NULL) {
    if (DEBUG) {
      printf("Open ELF file: %s\n", library_path);
    }
    FILE* fp = fopen(library_path, "r");
    return fp;
  }
  return NULL;
}

void CloseElfFile(FILE* elf_file) {
  if (elf_file != NULL) {
    if (DEBUG) {
      printf("Close ELF file\n");
    }
    fclose(elf_file);
  }
}

void GetElfHeader(Elf32_Ehdr* elf_header, FILE* elf_file) {
  if (elf_header == NULL || elf_file == NULL) {
    return;
  }
  fseek(elf_file, 0, SEEK_SET);
  fread(elf_header, sizeof(Elf32_Ehdr), 1, elf_file);
}

size_t GetShstrtabContent(char** shstrtab_content, FILE* elf_file) {
  if (elf_file == NULL) {
    return -1;
  }
  Elf32_Ehdr* elf_header = (Elf32_Ehdr*) malloc(sizeof(Elf32_Ehdr));
  GetElfHeader(elf_header, elf_file);
  off_t shstrtab_header_offset = elf_header->e_shoff + elf_header->e_shstrndx * sizeof(Elf32_Shdr);
  if (DEBUG) {
    printf("shstrtab header offset: %lx\n", shstrtab_header_offset);
  }
  free(elf_header);
  Elf32_Shdr* shstrtab_header = (Elf32_Shdr*) malloc(sizeof(Elf32_Shdr));
  fseek(elf_file, shstrtab_header_offset, SEEK_SET);
  fread(shstrtab_header, sizeof(Elf32_Shdr), 1, elf_file);
  off_t shstrtab_base_offset = shstrtab_header->sh_offset;
  size_t shstrtab_size = shstrtab_header->sh_size;
  if (DEBUG) {
    printf("shstrtab base offset: %ld, shstrtab size: %u\n", shstrtab_base_offset, shstrtab_size);
  }
  free(shstrtab_header);
  if (shstrtab_content == NULL) {
    *shstrtab_content = (char*) malloc(shstrtab_size * sizeof(char));
  } else {
    *shstrtab_content = (char*) realloc(shstrtab_content, shstrtab_size * sizeof(char));
  }
  fseek(elf_file, shstrtab_base_offset, SEEK_SET);
  fread(*shstrtab_content, shstrtab_size, 1, elf_file);
  return shstrtab_size;
}

void GetSectionHeaderByName(Elf32_Shdr* section_header, FILE* elf_file, const char* target_section_name) {
  if (elf_file == NULL || target_section_name == NULL || section_header == NULL) {
    return;
  }
  Elf32_Ehdr* elf_header = (Elf32_Ehdr*) malloc(sizeof(Elf32_Ehdr));
  GetElfHeader(elf_header, elf_file);
  size_t section_count = elf_header->e_shnum;
  off_t base_section_header_offset = elf_header->e_shoff;
  free(elf_header);
  if (DEBUG) {
    printf("section count: %u, base section header offset: %lx\n", section_count, base_section_header_offset);
  }
  char* shstrtab_content = NULL;
  GetShstrtabContent(&shstrtab_content, elf_file);
  for(int i = 0; i < section_count; ++i) {
    fseek(elf_file, base_section_header_offset, SEEK_SET);
    fread(section_header, sizeof(Elf32_Shdr), 1, elf_file);
    char* section_name = shstrtab_content + section_header->sh_name;
    if (strcmp(section_name, target_section_name) == 0) {
      if (DEBUG) {
        printf("index: %d, section name: %s\n", i, section_name);
      }
      break;
    }
    base_section_header_offset += sizeof(Elf32_Shdr);
  }
  free(shstrtab_content);
}

void PatchRemoteGot(pid_t pid, const char* library_path, long original_function_addr, long target_function_addr) {
  if (DEBUG) {
    printf("Get got content of %s in process %d\n", library_path, pid);
  }
  PtraceAttach(pid);
  FILE* elf_file = OpenElfFile(library_path);
  Elf32_Shdr* got_section_header = (Elf32_Shdr*) malloc(sizeof(Elf32_Shdr));
  GetSectionHeaderByName(got_section_header, elf_file, ".got");
  size_t got_section_size = got_section_header->sh_size;
  off_t got_addr_offset = got_section_header->sh_addr;
  free(got_section_header);
  if (DEBUG) {
    printf("got section size: %u, got addr offset: %lx\n", got_section_size, got_addr_offset);
  }
  long module_base_addr = GetModuleBaseAddr(pid, library_path);
  long got_section_address = module_base_addr + got_addr_offset;
  if (DEBUG) {
    printf("module base addr: %lx, got section address: %lx\n", module_base_addr, got_section_address);
  }
  for (int i = 0; i < got_section_size; i += sizeof(long)) {
    long got_entry = ptrace(PTRACE_PEEKDATA, pid, (void *)(got_section_address + i), NULL);
    if (got_entry == original_function_addr) {
      PtraceWrite(pid, (uint8_t*)(got_section_address + i), (uint8_t*)&target_function_addr, sizeof(long));
      if (DEBUG) {
        printf("hooked got entry %d: %lx with %lx\n", i / sizeof(long), got_entry, target_function_addr);
      }
    }
  }
  PtraceDetach(pid);
  CloseElfFile(elf_file);
}
