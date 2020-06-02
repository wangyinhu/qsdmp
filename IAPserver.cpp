//
// Created by yale on 7/27/18.
//
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include "IAPserver.h"
#include <dirent.h>
#include "Absflpu.h"
#include "Ylib.h"


#define EXTRA_ROM_FILE_NAME_LENGTH	100

/**
 * file name=ROM-(cid:2)-B(bank:1)-(baseaddress:8)-(version:4).bin
 * @param Bank0fileName  ROM-21-0003-B0-08001000.bin
 * @param Bank1fileName  ROM-21-0003-B1-08008000.bin
 * @return on success 0, on failure -1
 */
int IAPserver::loadROM(uint8_t cid) {
	char rom_prefix[ROM_FILE_verIdx + 1];
	sprintf(rom_prefix, "ROM-%02X-", cid);
	struct dirent *dirObject;
	char Bank0fileName[ROM_FILENAME_LENGTH + EXTRA_ROM_FILE_NAME_LENGTH];
	char Bank1fileName[ROM_FILENAME_LENGTH + EXTRA_ROM_FILE_NAME_LENGTH];
	bool filename0loaded = false;
	bool filename1loaded = false;
	auto directory = opendir(DEVICE_ROMS_DIR);

	if (directory) {
		while ((dirObject = readdir(directory)) != nullptr) {
			if (dirObject->d_type == DT_REG) {
				if (strncmp(dirObject->d_name, rom_prefix, ROM_FILE_verIdx) == 0 and
					strlen(dirObject->d_name) >= ROM_FILENAME_LENGTH and
						strlen(dirObject->d_name) < ROM_FILENAME_LENGTH	+ EXTRA_ROM_FILE_NAME_LENGTH) {
					auto bank_number = getBankNum(dirObject->d_name);
					if(bank_number == 0){
						strcpy(Bank0fileName, dirObject->d_name);
						filename0loaded = true;
					} else if(bank_number == 1){
						strcpy(Bank1fileName, dirObject->d_name);
						filename1loaded = true;
					}
				}
			}
		}
		closedir(directory);
	} else {
		PRINTLOGF(YLOG_WARNING, "error! opendir DEVICE_ROMS_DIR='%s' fail. error=%s\n"
								, DEVICE_ROMS_DIR, strerror(errno));
	}
	if (not filename0loaded or not filename1loaded) {
		PRINTLOGF(YLOG_WARNING, "error! NOT both ROM files are loaded\n"
								"bank0 bool=%d loaded, bank1 bool=%d loaded.\n", filename0loaded, filename1loaded);
		return -1;
	}
	auto verNum = getVersion(Bank0fileName);
	if (verNum != getVersion(Bank1fileName)) {
		PRINTLOGF(YLOG_WARNING, "error! TWO ROM bank version not identical.\n"
								"bank0 version=%d, bank1 version=%d.\n",
				  getVersion(Bank0fileName), getVersion(Bank1fileName));
		return -1;
	} else{
		versionNum = verNum;
		PRINTLOGF(YLOG_NOTICE, "versionNum=%u\n", versionNum);
	}

	PRINTLOGF(YLOG_INFO, "-----------------------%-40s------------------------\n",
			  Bank0fileName);
	baseAddress0 = getBaseAddress(Bank0fileName);
	PRINTLOGF(YLOG_NOTICE, "baseAddress0=0x%08lX\n", baseAddress0);
	if(0 != loadROMFile(Bank0fileName, ROMBank0, checkSum0)){
		return -1;
	}
	PRINTLOGF(YLOG_INFO, "-----------------------%-40s------------------------\n",
			  Bank1fileName);
	baseAddress1 = getBaseAddress(Bank1fileName);
	PRINTLOGF(YLOG_NOTICE, "baseAddress1=0x%08lX\n", baseAddress1);
	if(0 != loadROMFile(Bank1fileName, ROMBank1, checkSum1)){
		return -1;
	}
	loadStatus = true;
	return versionNum;
}


int IAPserver::loadROMFile(const char * BankFilename, std::vector<uint8_t> &ROMBank, uint32_t &checkSum){
	uint8_t buf[ROMBINSIZEMAX];
	char filePath[300];
	sprintf(filePath, "%s%s", DEVICE_ROMS_DIR, BankFilename);
	PRINTLOGF(YLOG_NOTICE, "loading ROM%d from file=%s...\n", getBankNum(BankFilename), filePath);
	auto fd = open(filePath, O_RDONLY);
	if (fd > 0) {
		auto length = read(fd, buf, ROMBINSIZEMAX - 1);
		if (length > 0 && length < ROMBINSIZEMAX - 1) {
			buf[length] = 0;
			auto romSize = (uint32_t)length & 0xffffcU;
			if ((uint32_t)length & 0x3U) {
				romSize += 4;
			}
			ROMBank.resize(romSize, 0xff);
			memcpy(ROMBank.data(), buf, (uint32_t)length);
			checkSum = crc32(0, ROMBank.data(), romSize);
			PRINTLOGF(YLOG_NOTICE, "checkSum=0x%08X\n", checkSum);
			close(fd);
			PRINTLOGF(YLOG_NOTICE, "%s loaded, length=%d, loaded romSize=%d\n", BankFilename, length, romSize);
			PRINTLOGF(YLOG_DEBUG, "data=%s\n", buf);
			return 0;
		} else if(length == ROMBINSIZEMAX - 1){
			PRINTLOGF(YLOG_WARNING, "error! read %s fail, error=(rom size too big)\n", BankFilename);
			close(fd);
			return -1;
		} else {
			PRINTLOGF(YLOG_WARNING, "error! read %s fail, error=%s\n", BankFilename, strerror(errno));
			close(fd);
			return -1;
		}
	} else {
		PRINTLOGF(YLOG_WARNING, "error! open Bank fail, path='%s'\n"
								"error=%s\n", filePath, strerror(errno));
		return -1;
	}
}


int IAPserver::getCode(uint64_t address, uint16_t length, uint8_t *dataOut, uint16_t &outLength) const {
	if (baseAddress0 <= address and address < baseAddress0 + ROMBank0.size()) {
		auto leftSize = baseAddress0 + ROMBank0.size() - address;
		if (leftSize <= length) {
			outLength = (uint16_t) leftSize;
		} else {
			outLength = length;
		}
		memcpy(dataOut, &ROMBank0.data()[address - baseAddress0], outLength);
		return 0;
	} else if (baseAddress1 <= address and address < baseAddress1 + ROMBank1.size()) {
		auto leftSize = baseAddress1 + ROMBank1.size() - address;
		if (leftSize <= length) {
			outLength = (uint16_t) leftSize;
		} else {
			outLength = length;
		}
		memcpy(dataOut, &ROMBank1.data()[address - baseAddress1], outLength);
		return 0;
	} else {
		return -1;
	}
}

uint16_t IAPserver::getVersion(const char *fileName) {
	return (uint16_t) std::stoi(fileName + ROM_FILE_verIdx, nullptr, 16);
}

uint32_t IAPserver::getBaseAddress(const char *fileName) {
	return (uint32_t)std::stoi(fileName + ROM_FILE_basIdx, nullptr, 16);
}

uint32_t IAPserver::getBankNum(const char *fileName) {
	return (uint32_t)std::stoi(fileName + ROM_FILE_bnkIdx, nullptr, 16);
}

bool IAPserver::isLoaded(void) const {
	return loadStatus;
}

uint16_t IAPserver::getVersionNum() const {
	return versionNum;
}

uint32_t IAPserver::getCheckSum(uint32_t baseAddress) const {
	if (baseAddress == baseAddress0) {
		return checkSum0;
	} else {
		return checkSum1;
	}
}

bool IAPserver::isBaseAddress(uint32_t baseAddress) const {
	return(baseAddress == baseAddress0 or baseAddress == baseAddress1);
}

uint32_t IAPserver::getCodeLength(uint32_t baseAddress) const {
	if (baseAddress == baseAddress0) {
		return (uint32_t)ROMBank0.size();
	} else {
		return (uint32_t)ROMBank1.size();
	}
}


