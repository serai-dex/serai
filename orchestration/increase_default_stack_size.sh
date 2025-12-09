#!/bin/sh

# Raises `PT_GNU_STACK`'s memory to be at least 8 MB.
#
# This causes `musl` to use a 8 MB default for new threads, resolving the primary
# compatibility issue faced when executing a program on a `musl` system.
#
# See https://wiki.musl-libc.org/functional-differences-from-glibc.html#Thread-stack-size
# for reference. This differs that instead of setting at time of link, it
# patches the binary as an already-linked ELF executable.

set -e

ELF="$1"
if [ ! -f "$ELF" ]; then
  echo "\`increase_default_stack_size.sh\` [ELF binary]"
  echo ""
  echo "Sets the \`PT_GNU_STACK\` program header to its existing value or 8 MB,"
  echo "whichever is greater."
  exit 1
fi

hex() {
  od -tx1 -v -A none | tr -d "[:space:]"
}
read_bytes() {
   dd bs=1 skip="$1" count="$2" if="$ELF" 2> /dev/null | hex
}
write_bytes() {
  POS=$1
  BYTES=$2
  while [ ! "$BYTES" = "" ]; do
    NEXT=$(printf "%s" "$BYTES" | head -c2)
    # Advance to the third byte, as in, after the first two bytes
    BYTES=$(printf "%s" "$BYTES" | tail -c+3)

    # shellcheck disable=SC2059
    printf "\x$NEXT" | dd conv=notrunc bs=1 seek="$POS" of="$ELF" 2> /dev/null
    POS=$((POS + 1))
  done
}

# Magic
MAGIC=$(read_bytes 0 4)
EXPECTED_MAGIC=$(printf "\x7ELF" | hex)
if [ ! "$MAGIC" = "$EXPECTED_MAGIC" ]; then
  echo "Not ELF"
  exit 2
fi

# 1 if 32-bit, 2 if 64-bit
BITS=$(read_bytes 4 1)
case $BITS in
  "01") BITS=32;;
  "02") BITS=64;;
  *)
    echo "Not 32- or 64- bit"
    exit 3
    ;;
esac

# For `value_per_bits a b`, `a` if 32-bit and `b` if 64-bit
value_per_bits() {
  RESULT=$(($1))
  if [ $BITS = 64 ]; then
    RESULT=$(($2))
  fi
  printf "%s" "$RESULT"
}

# Read an integer by its offset, differing depending on if 32- or 64-bit
read_integer_by_offset() {
  OFFSET=$(value_per_bits "$1" "$2")
  BYTES=$(read_bytes "$OFFSET" "$3")
  BYTES=$(swap_native_endian "$BYTES")
  printf "%i" $(( 0x$BYTES ))
}

# 1 if little-endian, 2 if big-endian
LITTLE_ENDIAN=$(read_bytes 5 1)
case $LITTLE_ENDIAN in
  "01") LITTLE_ENDIAN=1;;
  "02") LITTLE_ENDIAN=0;;
  *)
    echo "Not little- or big- endian"
    exit 4
    ;;
esac

# While this script is written in big-endian, we need to work with the file in
# its declared endian. This function swaps from big to native, or vice versa,
# as necessary.
swap_native_endian() {
  BYTES="$1"
  if [ "$BYTES" = "" ]; then
    read -r BYTES
  fi

  if [ "$LITTLE_ENDIAN" -eq 0 ]; then
    printf "%s" "$BYTES"
    return
  fi

  while [ ! "$BYTES" = "" ]; do
    printf "%s" "$BYTES" | tail -c2
    BYTES=$(printf "%s" "$BYTES" | head -c-2)
  done
}

ELF_VERSION=$(read_bytes 6 1)
if [ ! "$ELF_VERSION" = "01" ]; then
  echo "Unknown ELF Version ($ELF_VERSION)"
  exit 5
fi

ELF_VERSION_2=$(read_bytes $((0x14)) 4)
if [ ! "$ELF_VERSION_2" = "$(swap_native_endian 00000001)" ]; then
  echo "Unknown secondary ELF Version ($ELF_VERSION_2)"
  exit 6
fi

# Find where the program headers are
PROGRAM_HEADERS_OFFSET=$(read_integer_by_offset 0x1c 0x20 "$(value_per_bits 4 8)")
PROGRAM_HEADER_SIZE=$(value_per_bits 0x20 0x38)
DECLARED_PROGRAM_HEADER_SIZE=$(read_integer_by_offset 0x2a 0x36 2)
if [ ! "$PROGRAM_HEADER_SIZE" -eq "$DECLARED_PROGRAM_HEADER_SIZE" ]; then
  echo "Unexpected size of a program header ($DECLARED_PROGRAM_HEADER_SIZE)"
  exit 7
fi
program_header_start() {
  printf "%i" $((PROGRAM_HEADERS_OFFSET + ($1 * PROGRAM_HEADER_SIZE)))
}
read_program_header() {
  START=$(program_header_start "$1")
  read_bytes "$START" "$PROGRAM_HEADER_SIZE"
}

# Iterate over each program header
PROGRAM_HEADERS=$(read_integer_by_offset 0x2c 0x38 2)
NEXT_PROGRAM_HEADER=$(( PROGRAM_HEADERS - 1 ))
FOUND=0
while [ "$NEXT_PROGRAM_HEADER" -ne -1 ]; do
  THIS_PROGRAM_HEADER=$NEXT_PROGRAM_HEADER
  NEXT_PROGRAM_HEADER=$(( NEXT_PROGRAM_HEADER - 1 ))
  PROGRAM_HEADER=$(read_program_header "$THIS_PROGRAM_HEADER")

  HEADER_TYPE=$(printf "%s" "$PROGRAM_HEADER" | head -c8)
  HEADER_TYPE=$(swap_native_endian "$HEADER_TYPE")
  # `PT_GNU_STACK`
  # https://github.com/torvalds/linux/blob/c2f2b01b74be8b40a2173372bcd770723f87e7b2/include/uapi/linux/elf.h#L41
  if [ ! "$HEADER_TYPE" = "6474e551" ]; then
    continue
  fi
  FOUND=1

  MEMSZ_OFFSET=$(( $(program_header_start "$THIS_PROGRAM_HEADER") + $(value_per_bits 0x14 0x28) ))
  MEMSZ_LEN=$(value_per_bits 4 8)
  # `MEMSZ_OFFSET MEMSZ_OFFSET` as we've already derived it depending on the amount of bits
  MEMSZ=$(read_integer_by_offset "$MEMSZ_OFFSET" "$MEMSZ_OFFSET" "$MEMSZ_LEN")
  DESIRED_STACK_SIZE=$((8 * 1024 * 1024))
  # Only run if the inherent value is _smaller_
  if [ "$MEMSZ" -lt "$DESIRED_STACK_SIZE" ]; then
    # `2 *`, as this is its length in hexadecimal
    HEX_MEMSZ=$(printf %."$((2 * MEMSZ_LEN))"x "$DESIRED_STACK_SIZE")
    HEX_MEMSZ=$(swap_native_endian "$HEX_MEMSZ")
    write_bytes "$MEMSZ_OFFSET" "$HEX_MEMSZ"
  fi
done

if [ "$FOUND" -eq 0 ]; then
  echo "\`PT_GNU_STACK\` program header not found"
  exit 8
fi

echo "All instances of \`PT_GNU_STACK\` patched to be at least 8 MB"
exit 0
