CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2
TARGET  = logparse
SRC     = logparse.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

test: $(TARGET) test_auth.log
	@echo "=== Full parse ==="
	./$(TARGET) test_auth.log
	@echo ""
	@echo "=== Filter: Failed password ==="
	./$(TARGET) -f "Failed password" test_auth.log
	@echo ""
	@echo "=== CSV output ==="
	./$(TARGET) -c -n 3 test_auth.log
	@echo ""
	@echo "=== Stats only ==="
	./$(TARGET) -s test_auth.log
