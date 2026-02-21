package pe

import (
	"encoding/binary"
	"fmt"
	"os"
)

// IsNETAssembly checks if a PE file is a .NET assembly by reading the CLR
// Runtime Header entry in the PE data directories. It only reads the first
// ~512 bytes of the file.
func IsNETAssembly(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// Read enough bytes to cover PE headers (512 bytes is plenty)
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil {
		return false, fmt.Errorf("read PE header: %w", err)
	}
	buf = buf[:n]

	// 1. Check MZ signature
	if n < 2 || buf[0] != 'M' || buf[1] != 'Z' {
		return false, nil
	}

	// 2. Read PE signature offset at 0x3C
	if n < 0x3C+4 {
		return false, nil
	}
	peOffset := int(binary.LittleEndian.Uint32(buf[0x3C:]))

	// 3. Verify PE\0\0 signature
	if peOffset+4 > n {
		return false, nil
	}
	if buf[peOffset] != 'P' || buf[peOffset+1] != 'E' || buf[peOffset+2] != 0 || buf[peOffset+3] != 0 {
		return false, nil
	}

	// 4. Skip COFF header (20 bytes) to Optional Header
	optHeaderOffset := peOffset + 4 + 20

	// 5. Check Optional Header magic
	if optHeaderOffset+2 > n {
		return false, nil
	}
	magic := binary.LittleEndian.Uint16(buf[optHeaderOffset:])

	var dataDirOffset int
	switch magic {
	case 0x10b: // PE32
		dataDirOffset = optHeaderOffset + 96
	case 0x20b: // PE32+ (64-bit)
		dataDirOffset = optHeaderOffset + 112
	default:
		return false, nil
	}

	// 6. CLR Runtime Header is data directory index 14 (zero-based)
	// Each data directory entry is 8 bytes (4 VirtualAddress + 4 Size)
	clrEntryOffset := dataDirOffset + 14*8
	if clrEntryOffset+8 > n {
		return false, nil
	}

	rva := binary.LittleEndian.Uint32(buf[clrEntryOffset:])
	size := binary.LittleEndian.Uint32(buf[clrEntryOffset+4:])

	return rva != 0 && size != 0, nil
}
