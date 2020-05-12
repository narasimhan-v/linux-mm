CC = gcc
CFLAGS  = -g -Wall -lpthread
TARGET = random

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)
