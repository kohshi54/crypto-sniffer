all: up

up:
	sudo python3 -E trace.py

user:
	gcc -O0 ./test.c
	./a.out

find:
	objdump -d ./a.out | grep change_buf

