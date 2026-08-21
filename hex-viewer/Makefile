CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2
TARGET  = hexview
SRC     = hexview.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "=== Self-test: hex dump of own binary ==="
	./$(TARGET) -n 128 $(TARGET)
	@echo ""
	@echo "=== Search test: looking for 'ELF' header ==="
	./$(TARGET) -s "ELF" -n 64 $(TARGET)
