CC = gcc
# CFLAGS += -Wall -pedantic -D_DEFAULT_SOURCE -g
CFLAGS += -std=c99 -Wall -pedantic -D_DEFAULT_SOURCE -g
INCLUDES = -I../include

TMP = ./tmp

PACKET_OBJECT_FILES = \
	$(TMP)/packet_cache.o \
	$(TMP)/packet_test.o

VERDICT_OBJECT_FILES = \
	$(TMP)/verdict_cache.o \
	$(TMP)/verdict_test.o \
	$(TMP)/utils.o

test: packet_test verdict_test example

packet_test: $(TMP)/packet_test
	@echo "\n\n----- START PACKET CACHE TEST ----- \n\n"
	@$(TMP)/packet_test
	@echo "\n\n----- END PACKET CACHE TEST ----- \n\n"

$(TMP)/packet_test: $(PACKET_OBJECT_FILES)
	@mkdir -p $(TMP)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $(TMP)/packet_test $(PACKET_OBJECT_FILES)

verdict_test: $(TMP)/verdict_test
	@echo "\n\n----- START VERDICT CACHE TEST ----- \n\n"
	@$(TMP)/verdict_test
	@echo "\n\n----- END VERDICT CACHE TEST ----- \n\n"

$(TMP)/verdict_test: $(VERDICT_OBJECT_FILES)
	@mkdir -p $(TMP)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $(TMP)/verdict_test $(VERDICT_OBJECT_FILES)

example: $(TMP)/example
	@echo "\n\n----- START EXAMPLE ----- \n\n"
	@$(TMP)/example
	@echo "\n\n----- END EXAMPLE ----- \n\n"

$(TMP)/example: $(PACKET_OBJECT_FILES) $(VERDICT_OBJECT_FILES) $(TMP)/example.o
	@mkdir -p $(TMP)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $(TMP)/example $(TMP)/packet_cache.o $(TMP)/verdict_cache.o $(TMP)/utils.o $(TMP)/example.o

$(TMP)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -c -o $@ $<
 $(LDFLAGS)

clean:
	rm -rf $(TMP)

.PHONY: all packet_test verdict_test test clean
