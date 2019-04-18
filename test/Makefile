CC = gcc
# CFLAGS += -Wall -pedantic -D_DEFAULT_SOURCE -g
CFLAGS += -std=c99 -Wall -pedantic -D_DEFAULT_SOURCE -g
INCLUDES = -I../include

TMP = ./tmp

CHECKSUM_OBJECT_FILES = \
	$(TMP)/checksum_test.o \
	$(TMP)/pm_checksum.o

test: checksum_test

checksum_test: $(TMP)/checksum_test
	@echo "\n\n----- START CHECKSUM TEST ----- \n\n"
	@$(TMP)/checksum_test
	@echo "\n\n----- END CHECKSUM TEST ----- \n\n"

$(TMP)/checksum_test: $(CHECKSUM_OBJECT_FILES)
	@mkdir -p $(TMP)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -o $(TMP)/checksum_test $(CHECKSUM_OBJECT_FILES)

$(TMP)/pm_checksum.o: ../sys/pm_checksum.c
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -c -o $@ $< $(LDFLAGS)

$(TMP)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTFLAGS) -c -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(TMP)

.PHONY: all checksum_test test clean
