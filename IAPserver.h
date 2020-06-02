//
// Created by yale on 7/27/18.
//

#ifndef QSDMP_IAPSERVER_H
#define QSDMP_IAPSERVER_H

#include <cstdint>
#include <vector>
#include <string>


#define  ROMBINSIZEMAX        0X100000U        //1M bytes
#define  DEVICE_ROMS_DIR      "DEVICE_ROMS/"


class IAPserver {
public:
	int loadROM(uint8_t cid);

	int getCode(uint64_t address, uint16_t length, uint8_t *dataOut, uint16_t &outLength) const;

	bool isLoaded(void) const;

	uint16_t getVersionNum() const;

	uint32_t getCheckSum(uint32_t baseAddress) const;

	uint32_t getCodeLength(uint32_t baseAddress) const;

	bool isBaseAddress(uint32_t baseAddress) const;

	//ROM-<CID(2)>-<VERSION(4)>-B<BANK(1)>-<BASEADDRESS(8)>.bin
	static auto constexpr ROM_FILENAME_LENGTH = strlen("ROM-21-0003-B0-08001000.bin");
	static auto constexpr ROM_FILE_verIdx = strlen("ROM-21-");
	static auto constexpr ROM_FILE_basIdx = strlen("ROM-21-0003-B0-");
	static auto constexpr ROM_FILE_bnkIdx = strlen("ROM-21-0003-B");

private:
	uint16_t versionNum;
	uint32_t baseAddress0;
	uint32_t baseAddress1;
	uint32_t checkSum0;
	uint32_t checkSum1;
	std::vector<uint8_t> ROMBank0;
	std::vector<uint8_t> ROMBank1;
	bool loadStatus = false;

	int loadROMFile(const char * filename, std::vector<uint8_t> &ROMBank1, uint32_t &checkSum1);

	uint16_t getVersion(const char *fileName);

	uint32_t getBaseAddress(const char *fileName);

	uint32_t getBankNum(const char *fileName);
};


#endif //QSDMP_IAPSERVER_H
