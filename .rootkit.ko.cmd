cmd_/home/wh1t3r0se/rootkit/rootkit.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000  --build-id  -T ./scripts/module-common.lds -o /home/wh1t3r0se/rootkit/rootkit.ko /home/wh1t3r0se/rootkit/rootkit.o /home/wh1t3r0se/rootkit/rootkit.mod.o;  true
