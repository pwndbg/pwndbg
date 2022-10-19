
all:
	gcc binary.c -o binary

core:
	gdb binary --nx --nh -ex run -ex 'generate-core-file core' -ex 'set confirm off' -ex quit
