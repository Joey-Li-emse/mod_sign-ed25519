1) Compile the kernel image from this branch https://github.com/thisway23/linux-kvm-sec/tree/pv-guest

2) Run:

```
./sign_image <path_to_compiled_image>
```

3) Copy hex output into EL2.
Sign module for KINT loading
