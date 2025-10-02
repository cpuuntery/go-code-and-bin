package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"log"
)

const (
	MBR_SIGNATURE = 0xAA55
	GPT_SIGNATURE = "EFI PART"
	SECTOR_SIZE   = 512
	PARTITION_ENTRY_COUNT = 128
	PARTITION_ENTRY_SIZE = 128
)

// GPT Header (first 92 bytes we care about)
type GPTHeader struct {
	Signature          [8]byte
	Revision           uint32
	HeaderSize         uint32
	HeaderCRC32        uint32
	Reserved           uint32
	CurrentLBA         uint64
	BackupLBA          uint64
	FirstUsableLBA     uint64
	LastUsableLBA      uint64
	DiskGUID           [16]byte
	PartitionTableLBA  uint64
	NumPartitions      uint32
	PartitionEntrySize uint32
	PartitionTableCRC  uint32
}

// GPT Partition Entry (128 bytes)
type GPTPartition struct {
	TypeGUID      [16]byte
	PartitionGUID [16]byte
	StartLBA      uint64
	EndLBA        uint64
	Attributes    uint64
	Name          [72]byte // UTF-16LE
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <disk image>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]
	f, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer f.Close()

	// Get file size
	fileInfo, err := f.Stat()
	if err != nil {
		log.Fatalf("Error getting file info: %v", err)
	}
	fileSize := fileInfo.Size()
	lastSector := uint64(fileSize) / SECTOR_SIZE - 1

	// Read the GPT header (LBA 1, offset 512)
	gptHeader := GPTHeader{}
	_, err = f.Seek(SECTOR_SIZE, io.SeekStart)
	if err != nil {
		log.Fatalf("Error seeking to GPT header: %v", err)
	}

	err = binary.Read(f, binary.LittleEndian, &gptHeader)
	if err != nil {
		log.Fatalf("Error reading GPT header: %v", err)
	}

	// Verify signature
	sig := string(gptHeader.Signature[:])
	if sig != GPT_SIGNATURE {
		log.Fatalf("Invalid GPT signature: expected %s, got %s", GPT_SIGNATURE, sig)
	}

	// Update header with correct file size information
	gptHeader.LastUsableLBA = lastSector - 33 // Reserve space for backup GPT
	gptHeader.BackupLBA = lastSector

	// Read all partition entries
	partitions := make([]GPTPartition, PARTITION_ENTRY_COUNT)
	_, err = f.Seek(int64(gptHeader.PartitionTableLBA)*SECTOR_SIZE, io.SeekStart)
	if err != nil {
		log.Fatalf("Error seeking to partition table: %v", err)
	}

	for i := 0; i < PARTITION_ENTRY_COUNT; i++ {
		err = binary.Read(f, binary.LittleEndian, &partitions[i])
		if err != nil {
			log.Fatalf("Error reading partition %d: %v", i, err)
		}
	}

	// Calculate new partition positions starting right after GPT structures
	// GPT structures take 34 sectors: 1 (header) + 33 (partition entries)
	nextFreeSector := uint64(34)
	
	for i := 0; i < PARTITION_ENTRY_COUNT; i++ {
		// Skip empty partitions
		if isZero(partitions[i].TypeGUID[:]) {
			continue
		}

		// Calculate partition size
		partitionSize := partitions[i].EndLBA - partitions[i].StartLBA + 1
		
		// Update partition start and end LBAs
		partitions[i].StartLBA = nextFreeSector
		partitions[i].EndLBA = nextFreeSector + partitionSize - 1
		
		// Move pointer to next free sector
		nextFreeSector = partitions[i].EndLBA + 1
	}

	// Update partition table CRC
	partitionTableBytes := make([]byte, PARTITION_ENTRY_COUNT*PARTITION_ENTRY_SIZE)
	for i := 0; i < PARTITION_ENTRY_COUNT; i++ {
		buf := make([]byte, PARTITION_ENTRY_SIZE)
		err = binary.Write(&byteBuffer{buf}, binary.LittleEndian, &partitions[i])
		if err != nil {
			log.Fatalf("Error serializing partition %d: %v", i, err)
		}
		copy(partitionTableBytes[i*PARTITION_ENTRY_SIZE:], buf)
	}
	gptHeader.PartitionTableCRC = crc32.ChecksumIEEE(partitionTableBytes)

	// Update header CRC (with CRC field zeroed during calculation)
	gptHeader.HeaderCRC32 = 0
	headerBytes := make([]byte, gptHeader.HeaderSize)
	err = binary.Write(&byteBuffer{headerBytes}, binary.LittleEndian, &gptHeader)
	if err != nil {
		log.Fatalf("Error serializing header: %v", err)
	}
	gptHeader.HeaderCRC32 = crc32.ChecksumIEEE(headerBytes)

	// Write updated header to primary location
	_, err = f.Seek(SECTOR_SIZE, io.SeekStart)
	if err != nil {
		log.Fatalf("Error seeking to primary header: %v", err)
	}
	err = binary.Write(f, binary.LittleEndian, &gptHeader)
	if err != nil {
		log.Fatalf("Error writing primary header: %v", err)
	}

	// Write updated partition table to primary location
	_, err = f.Seek(int64(gptHeader.PartitionTableLBA)*SECTOR_SIZE, io.SeekStart)
	if err != nil {
		log.Fatalf("Error seeking to partition table: %v", err)
	}
	for i := 0; i < PARTITION_ENTRY_COUNT; i++ {
		err = binary.Write(f, binary.LittleEndian, &partitions[i])
		if err != nil {
			log.Fatalf("Error writing partition %d: %v", i, err)
		}
	}

	// Create backup header (swap CurrentLBA and BackupLBA)
	backupHeader := gptHeader
	backupHeader.CurrentLBA = gptHeader.BackupLBA
	backupHeader.BackupLBA = gptHeader.CurrentLBA
	backupHeader.PartitionTableLBA = gptHeader.BackupLBA - 33 // Partition table is before backup header

	// Update backup header CRC
	backupHeader.HeaderCRC32 = 0
	backupHeaderBytes := make([]byte, backupHeader.HeaderSize)
	err = binary.Write(&byteBuffer{backupHeaderBytes}, binary.LittleEndian, &backupHeader)
	if err != nil {
		log.Fatalf("Error serializing backup header: %v", err)
	}
	backupHeader.HeaderCRC32 = crc32.ChecksumIEEE(backupHeaderBytes)

	// Write backup header
	_, err = f.Seek(int64(backupHeader.CurrentLBA)*SECTOR_SIZE, io.SeekStart)
	if err != nil {
		log.Fatalf("Error seeking to backup header: %v", err)
	}
	err = binary.Write(f, binary.LittleEndian, &backupHeader)
	if err != nil {
		log.Fatalf("Error writing backup header: %v", err)
	}

	// Write backup partition table
	_, err = f.Seek(int64(backupHeader.PartitionTableLBA)*SECTOR_SIZE, io.SeekStart)
	if err != nil {
		log.Fatalf("Error seeking to backup partition table: %v", err)
	}
	for i := 0; i < PARTITION_ENTRY_COUNT; i++ {
		err = binary.Write(f, binary.LittleEndian, &partitions[i])
		if err != nil {
			log.Fatalf("Error writing backup partition %d: %v", i, err)
		}
	}

	fmt.Println("GPT headers and partitions updated successfully!")
	fmt.Printf("File size: %d bytes (%d sectors)\n", fileSize, lastSector+1)
	fmt.Printf("Last usable sector: %d\n", gptHeader.LastUsableLBA)
	fmt.Printf("Backup header at sector: %d\n", gptHeader.BackupLBA)
}

// Helper function to check if a byte slice contains only zeros
func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Helper type to implement io.Writer for byte slices
type byteBuffer struct {
	b []byte
}

func (b *byteBuffer) Write(p []byte) (n int, err error) {
	n = copy(b.b, p)
	b.b = b.b[n:]
	return n, nil
}
