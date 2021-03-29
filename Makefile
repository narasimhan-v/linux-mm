CC = gcc
CFLAGS  = -g -Wall -lpthread
TARGET = random
all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c $(CFLAGS)

clean:
	$(RM) $(TARGET)
