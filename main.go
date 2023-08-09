package main

// Very basic tool, to solve a problem..
// https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
// https://opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld

import (
	// "archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "need file!")
		fmt.Fprintf(os.Stderr, "USAGE: %s <zip-file-name>\n", path.Base(os.Args[0]))
		os.Exit(2)
	}
	filename := os.Args[1]

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(data); i++ {
		if i < 4 {
			continue
		}
		buf := data[i-4 : i]
		if bytes.Equal(buf, []byte{0x50, 0x4b, 0x03, 0x04}) {
			fmt.Printf("\n** found file! @ %d\n", i-4)
			dumpFile(data, i-4)
		} else if bytes.Equal(buf, []byte{0x02, 0x01, 0x4b, 0x50}) {
			fmt.Printf("\n** found central! @ %d\n", i-4)
		}
	}
}

func dumpFile(data []byte, offset int) int {
	headerEndOffset, fileCompressedSize := dumpHeader(data, offset)
	fileEndOffset := headerEndOffset + int(fileCompressedSize)
	fmt.Printf("content: (%d)[%s]\n", fileCompressedSize, abriv(data[headerEndOffset:fileEndOffset], 16))
	return fileEndOffset
}

func dumpHeader(data []byte, offset int) (int, uint32) {
	ho := offset + 4
	fmt.Printf("version: %d\n", binary.LittleEndian.Uint16(data[ho:]))
	ho += 2
	fmt.Printf("flags: %08b:%08b\n", data[ho], data[ho+1])
	ho += 2
	fmt.Printf("compression: %d\n", binary.LittleEndian.Uint16(data[ho:]))
	ho += 2
	modtime := binary.LittleEndian.Uint16(data[ho:])
	sec := modtime & 0x001f
	min := (modtime >> 5) & 0x001f
	hour := (modtime >> 10) & 0x001f
	fmt.Printf("modtime(%04x): %02d:%02d:%02d\n", modtime, hour, min, sec*2)
	ho += 2
	moddate := binary.LittleEndian.Uint16(data[ho:])
	day := moddate & 0x001f
	month := (moddate >> 5) & 0x000f
	year := (moddate >> 9) & 0x00ff
	fmt.Printf("moddate(%04x): %d-%02d-%02d\n", moddate, year+1980, month, day)
	ho += 2
	fmt.Printf("crc-32: %04x\n", binary.LittleEndian.Uint32(data[ho:]))
	ho += 4
	compressedSize := binary.LittleEndian.Uint32(data[ho:])
	fmt.Printf("compressed-size: %d\n", compressedSize)
	ho += 4
	fmt.Printf("uncompressed-size: %d\n", binary.LittleEndian.Uint32(data[ho:]))
	ho += 4
	fnlen := binary.LittleEndian.Uint16(data[ho:])
	ho += 2
	eflen := binary.LittleEndian.Uint16(data[ho:])
	ho += 2
	fn := data[ho : ho+int(fnlen)]
	ho += int(fnlen)
	ef := data[ho : ho+int(eflen)]
	ho += int(eflen)
	fmt.Printf("filename(%d): %s\n", fnlen, fn)
	fmt.Printf("extrafield(%d):\n", eflen)
	dumpExtraField(ef)
	return ho, compressedSize
}

func dumpExtraField(data []byte) {
	o := 0
	for o < len(data) {
		hid := binary.LittleEndian.Uint16(data[o:])
		o += 2
		l := binary.LittleEndian.Uint16(data[o:])
		o += 2
		d := data[o : o+int(l)]
		o += int(l)
		switch hid {
		case 0x5455:
			dumpLUT(d)
		case 0x4453:
			dumpLSD(d)
		case 0x7875:
			dumpLux(d)
		default:
			fmt.Printf("\t0x%04x, data: (%d) %x\n", hid, l, d)
		}
	}
}

func dumpLux(data []byte) {
	o := 0
	version := data[o]
	o += 1
	uidSize := data[o]
	o += 1
	uid, _ := varUint(data, o, int(uidSize))
	o += int(uidSize)
	gidSize := data[o]
	o += 1
	gid, _ := varUint(data, o, int(gidSize))
	o += int(gidSize)
	fmt.Printf("\t0x7875 (\"ux\" New Unix Extra): version=%d, uid(%d)=%d, gid(%d)=%d\n",
		version,
		uidSize,
		uid,
		gidSize,
		gid,
	)
}
func varUint(data []byte, offset int, size int) (uint, error) {
	switch size {
	case 1:
		return uint(data[offset]), nil
	case 2:
		return uint(binary.LittleEndian.Uint16(data[offset:])), nil
	case 4:
		return uint(binary.LittleEndian.Uint32(data[offset:])), nil
	default:
		return 0, fmt.Errorf("unsupported int size: %d", size)
	}
}

func dumpLSD(data []byte) {
	o := 0
	bsize := binary.LittleEndian.Uint32(data[o:])
	o += 4
	version := data[o]
	o += 1
	ct := binary.LittleEndian.Uint16(data[o:])
	o += 2
	crc := binary.LittleEndian.Uint32(data[o:])
	o += 4
	fmt.Printf("\t0x4453 (\"SD\" Windows NT Security Descriptor): version=%d, uncomp-size=%d, comp-type=%d, crc=0x%x, (%d)[%s]\n",
		version,
		bsize,
		ct,
		crc,
		len(data)-o,
		abriv(data[o:], 16),
	)
}

func dumpLUT(data []byte) {
	o := 0
	flags := data[o]
	o += 1
	var mod uint32
	var ac uint32
	var cr uint32
	if flags&0x01 == 0x01 {
		mod = binary.LittleEndian.Uint32(data[o:])
	}
	o += 4
	if flags&0x02 == 0x02 {
		ac = binary.LittleEndian.Uint32(data[o:])
	}
	o += 4
	if flags&0x04 == 0x04 {
		cr = binary.LittleEndian.Uint32(data[o:])
	}
	fmt.Printf("\t0x5455 (\"UT\" Extended Timestamp): flags=%08b, mod=%s, ac=%s, cr=%s\n",
		flags,
		time.Unix(int64(mod), 0),
		time.Unix(int64(ac), 0),
		time.Unix(int64(cr), 0),
	)
}

func abriv(data []byte, length int) string {
	if length >= len(data) {
		return fmt.Sprintf("%x", data)
	}
	l1 := length / 2
	l2 := length - l1

	s1 := data[0:l1]
	s2 := data[len(data)-l2:]

	return fmt.Sprintf("%x...%x", s1, s2)
}
