CC = gcc
CFLAGS = -std=c99 -O3 -Wall -Wpedantic
DEPS = sha256.h
OBJ = cracker.o sha256.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
cracker: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
