#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#include "ed25519/src/ed25519.h"

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

#define PAGE_SIZE 4096


int format_elf_file(unsigned char * elfFile) {

	ElfW(Ehdr) *header; 
	ElfW(Shdr) *sechdrs;
	char *secstrings; 
	int i; 
	void * init_base, * text_base, * exit_base, * unlikely_base; 
	size_t init_size, text_size, exit_size, unlikely_size; 
	FILE * fd; 
	unsigned long init_padding, padding; 

	header = (ElfW(Ehdr) *) elfFile;

	sechdrs = (void *)header + header->e_shoff;
	secstrings = (void *)header + sechdrs[header->e_shstrndx].sh_offset;

	text_size = 0; 

	if (memcmp(header -> e_ident, ELFMAG, SELFMAG) == 0) {

		for (i = 0; i < header -> e_shnum; i ++)
		{	
			ElfW(Shdr) shdr = sechdrs[i];
			if (!strcmp(secstrings + shdr.sh_name, ".init.text")){
				init_base = (void *)(elfFile + shdr.sh_offset); 
				init_size = (size_t) shdr.sh_size; 
			}
			else if (!strcmp(secstrings + shdr.sh_name, ".text")){
				text_base = (void *)(elfFile + shdr.sh_offset); 
				text_size = (size_t) shdr.sh_size; 
			}
			else if (!strcmp(secstrings + shdr.sh_name, ".text.unlikely")){
				unlikely_base = (void *)(elfFile + shdr.sh_offset); 
				unlikely_size = (size_t) shdr.sh_size;
			}
			else if (!strcmp(secstrings + shdr.sh_name, ".exit.text")){
				exit_base = (void *)(elfFile + shdr.sh_offset);
				exit_size = (size_t) shdr.sh_size;
			}
		}

		init_padding = (init_size + PAGE_SIZE - 1UL) & ~(PAGE_SIZE - 1UL);
		padding = init_padding - init_size;
		fd = fopen("./mod_sign.dump","wb");
		fwrite(init_base, sizeof(char), init_size, fd);
		for (i = 0; i < padding; i ++)
			fputc(0, fd);
		fwrite(text_base, sizeof(char), text_size, fd); 
		fwrite(unlikely_base, sizeof(char), unlikely_size, fd); 
		fwrite(exit_base, sizeof(char), exit_size, fd);
		fclose(fd);

		return 0; 
    }
	else 
	{
		printf("\rElf file not valid\n");
		return 1; 
	}
}

void print_hex(unsigned char *buf, int len) {
	int i;
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

int main(int argc, char **argv) {
	unsigned char seed[32];
	unsigned char public_key[32];
	unsigned char private_key[64];
	unsigned char signature[64];
	int mod_img_fd, mod_img_sz, mod_code_fd, mod_code_sz;
	struct stat s, cs;
	unsigned char *f_data, *img_data;
	const char *kern_img_path;
	int verify_res = 0;
	int err; 

	if (argc == 1)
		kern_img_path = "/srv/vm/pv-guest";
	else
		kern_img_path = argv[1];
	
	if (ed25519_create_seed(seed)) {
		printf("error while generating seed\n");
		exit(1);
	}
	ed25519_create_keypair(public_key, private_key, seed);

	mod_img_fd = open(kern_img_path, O_RDONLY);
	fstat(mod_img_fd, &s);
	mod_img_sz = s.st_size;
	img_data = (unsigned char *) mmap(0, mod_img_sz, PROT_READ, MAP_PRIVATE, mod_img_fd, 0);

	err = format_elf_file(img_data);
	if (err)
		return 1;

	mod_code_fd = open("./mod_sign.dump", O_RDONLY);
	fstat(mod_code_fd, &cs);
	mod_code_sz = cs.st_size;
	f_data = (unsigned char *) mmap(0, mod_code_sz, PROT_READ, MAP_PRIVATE, mod_code_fd, 0);

	ed25519_sign(signature, f_data, mod_code_sz, public_key, private_key);

	printf("public_key=");
	print_hex(public_key, 32);
	printf("private_key=");
	print_hex(private_key, 64);
	printf("signature=");
	print_hex(signature, 64);

	verify_res = ed25519_verify(signature, f_data, mod_code_sz, public_key);

	munmap(img_data, mod_img_sz);
	munmap(f_data, mod_code_sz);

	printf("verify_res=%d\n", verify_res);
	return 0;
}
