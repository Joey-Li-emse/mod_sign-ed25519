SRC = $(shell find . -name "*.c")
OBJ = $(SRC:%.c=%.o)
HEADERS = $(shell find . -name "*.h")
TARGET = sign_image
CC = gcc
CFLAGS = -g -Wall

all: $(TARGET)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@

clean:
	-rm -f $(TARGET)
	-rm -f $(OBJ)
