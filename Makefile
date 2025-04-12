# Compiler and its flags.
CXX = gcc
CXXFLAGS = -std=c99 -Wall -Wextra -g -O1 -pedantic
OPENSSL = -lcrypto -lssl

# List of source files.
SOURCES = $(wildcard src/*.c)

# Object files.
OBJECTS = $(SOURCES:.c=.o)

# Output executable.
EXEC = gta4-decrypter

# Default target.
all: $(EXEC)

# Link the object files to create the executable.
$(EXEC): $(OBJECTS)
	$(CXX) $(OBJECTS) $(OPENSSL) -o $(EXEC)

# Compile the .c files to .o files.
%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up object files and the executable.
clean:
	rm -f $(OBJECTS) $(EXEC)

# Phony targets.
.PHONY: all clean
