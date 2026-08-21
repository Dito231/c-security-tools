CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2
TARGET  = procenum
SRC     = procenum.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "=== List all processes (first 20) ==="
	./$(TARGET) 2>&1 | head -21
	@echo ""
	@echo "=== Filter by current user ==="
	./$(TARGET) -u $$(whoami) 2>&1 | head -11
	@echo ""
	@echo "=== Sort by memory (top 10) ==="
	./$(TARGET) -t 2>&1 | head -11
	@echo ""
	@echo "=== Detail for PID 1 ==="
	./$(TARGET) -p 1
