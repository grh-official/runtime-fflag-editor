#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <Psapi.h>
#include <unordered_map>
#include <TlHelp32.h>
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/error/en.h"

template <typename T>
__forceinline T read(HANDLE proc, uintptr_t address)
{
	T value;
	ReadProcessMemory(proc, (LPVOID)address, &value, sizeof(value), 0);
	return value;
}

__forceinline void read(HANDLE proc, uintptr_t address, void* buffer, size_t size)
{
	ReadProcessMemory(proc, (LPVOID)address, buffer, size, 0);
}

template <typename T>
__forceinline void write(HANDLE proc, uintptr_t address, T value)
{
	WriteProcessMemory(proc, (LPVOID)address, &value, sizeof(value), 0);
}

__forceinline void write(HANDLE proc, uintptr_t address, void* buffer, size_t size)
{
	WriteProcessMemory(proc, (LPVOID)address, buffer, size, 0);
}

enum FVarType
{
	fvar_bool,
	fvar_int,
	fvar_string,
	fvar_log
};

struct FVarDescriptor
{
	FVarType type;
	uint32_t rva;

	virtual bool set(HANDLE proc, std::string _value) = 0;
};

struct FVarDescriptorBool : FVarDescriptor
{
	virtual bool set(HANDLE proc, std::string _value)
	{
		uintptr_t roblox_base;
		DWORD _;
		K32EnumProcessModules(proc, (HMODULE*)&roblox_base, 8, &_);

		if (_value == "true" || _value == "True")
		{
			write(proc, roblox_base + rva, true);
			return true;
		}
		else if (_value == "false" || _value == "False")
		{
			write(proc, roblox_base + rva, false);
			return true;
		}
		else if (_value.size() && _value[0] >= '0' && _value[1] <= '9')
		{
			write(proc, roblox_base + rva, std::stoull(_value) != 0);
			return true;
		}

		return false;
	}
};

struct FVarDescriptorInt : FVarDescriptor
{
	virtual bool set(HANDLE proc, std::string _value)
	{
		uintptr_t roblox_base;
		DWORD _;
		K32EnumProcessModules(proc, (HMODULE*)&roblox_base, 8, &_);

		if (_value.size() > 2 && _value[0] == '0' && tolower(_value[1]) == 'x')
		{
			write(proc, roblox_base + rva, std::stol(_value.substr(2), nullptr, 16));
			return true;
		}
		else if (_value.size() && _value[0] >= '0' && _value[1] <= '9')
		{
			write(proc, roblox_base + rva, std::stol(_value));
			return true;
		}

		return false;
	}
};

struct FVarDescriptorString : FVarDescriptor
{
	virtual bool set(HANDLE proc, std::string _value)
	{
		uintptr_t roblox_base;
		DWORD _;
		K32EnumProcessModules(proc, (HMODULE*)&roblox_base, 8, &_);

		if (_value.size() >= 0x10)
		{
			// this will require recreation of internal roblox heap allocation
			return false;
		}
		else
		{
			write(proc, roblox_base + rva, &_value, sizeof(_value));
			return true;
		}

		return false;
	}
};

struct FVarDescriptorLog : FVarDescriptor
{
	virtual bool set(HANDLE proc, std::string _value)
	{
		uintptr_t roblox_base;
		DWORD _;
		K32EnumProcessModules(proc, (HMODULE*)&roblox_base, 8, &_);

		if (_value.size() > 2 && _value[0] == '0' && tolower(_value[1]) == 'x')
		{
			write(proc, roblox_base + rva, (uint8_t)std::stol(_value.substr(2), nullptr, 16));
			return true;
		}
		else if (_value.size() && _value[0] >= '0' && _value[0] <= '9')
		{
			write(proc, roblox_base + rva, (uint8_t)std::stol(_value));
			return true;
		}
		else if (_value.size() > 1 && _value[0] == 'F')
		{
			_value = _value.substr(1);
			if (_value.size() > 2 && _value[0] == '0' && tolower(_value[1]) == 'x')
			{
				write(proc, roblox_base + rva, (uint16_t)std::stol(_value.substr(2), nullptr, 16));
				return true;
			}
			else if (_value.size() && _value[0] >= '0' && _value[0] <= '9')
			{
				write(proc, roblox_base + rva, (uint16_t)std::stol(_value));
				return true;
			}
		}

		return false;
	}
};

// removed due to requirement to disable fvar being refetched per process
//std::unordered_map<std::string, FVarDescriptor*> cached_fvar_descriptors = {};

uintptr_t cached_fvar_container_rva = 0;
uintptr_t get_fvar_container(HANDLE proc)
{
	uintptr_t roblox_base;
	DWORD _;
	K32EnumProcessModules(proc, (HMODULE*)&roblox_base, 8, &_);
	if (cached_fvar_container_rva)
		return roblox_base + cached_fvar_container_rva;

	char* ptr = (char*)roblox_base + 0x500000;
	MEMORY_BASIC_INFORMATION mbi;
	while (VirtualQueryEx(proc, ptr, &mbi, sizeof(mbi)))
	{
		if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
		{
			uint8_t* buffer = (uint8_t*)malloc(mbi.RegionSize);
			read(proc, (uintptr_t)mbi.BaseAddress, buffer, mbi.RegionSize);

			uint8_t* end = buffer + mbi.RegionSize - 0x30;
			for (uint8_t* curr = buffer; curr < end; curr++)
			{
				// 48 83 EC 38 48 8B 0D ? ? ? ? 4C 8D 05 ? ? ? ? 41 B9
				if ((*(uintptr_t*)(curr) & 0x00FFFFFFFFFFFFFF) == 0x000D8B4838EC8348 && (*(uint32_t*)(curr + 0xB) & 0x00FFFFFF) == 0x00058D4C && *(uint16_t*)(curr + 0x12) == 0xB941)
				{
					uintptr_t fvar_container = roblox_base + (curr - buffer) + ((uintptr_t)mbi.BaseAddress - roblox_base) + 0xB + *(int*)(curr + 0x7);
					cached_fvar_container_rva = fvar_container - roblox_base;
					free(buffer);
					return fvar_container;
				}
			}

			free(buffer);
		}

		ptr = (char*)mbi.BaseAddress + mbi.RegionSize;
	}

	return 0;
}

int cached_rva_offset = 0;
FVarDescriptor* lookup_entry(HANDLE proc, uintptr_t fvar_container, std::string fvar)
{
	uintptr_t roblox_base;
	DWORD _;
	K32EnumProcessModules(proc, (HMODULE*)&roblox_base, 8, &_);

	uintptr_t map = read<uintptr_t>(proc, fvar_container);

	uintptr_t hash = 0xCBF29CE484222325;
	
	const char* cstr = fvar.c_str();
	size_t size = fvar.size();
	
	for (size_t i = 0; i < size; i++)
		hash = 0x100000001B3 * ((uintptr_t)(uint8_t)cstr[i] ^ hash);

	uintptr_t index = (hash & read<uintptr_t>(proc, map + 0x30)) << 4;
	
	uintptr_t container = read<uintptr_t>(proc, map + 0x18);

	uintptr_t entry = read<uintptr_t>(proc, container + 0x8 + index);

	uintptr_t end = read<uintptr_t>(proc, map + 0x8);

	if (entry == end) 
		return 0;

	end = read<uintptr_t>(proc, container + index);

	uint8_t* buffer = (uint8_t*)malloc(size);
	while (true)
	{
		uint8_t entry_data[0x38];
		read(proc, entry, entry_data, sizeof(entry_data));

		if (*(size_t*)(entry_data + 0x20) == size)
		{
			if (size >= 0x10)
				read(proc, *(uintptr_t*)(entry_data + 0x10), buffer, size);
			else
				memcpy(buffer, entry_data + 0x10, size);

			if (memcmp(cstr, buffer, size) == 0)
			{
				free(buffer);

				uintptr_t getset = *(uintptr_t*)(entry_data + 0x30);
				if (!getset)
					return nullptr;

				uintptr_t vftable = read<uintptr_t>(proc, getset);
				if (!vftable)
					return nullptr;

				uintptr_t desc = read<uintptr_t>(proc, vftable - 0x8);
				if (!desc)
					return nullptr;

				uint32_t name_rva = read<uint32_t>(proc, desc + 0xC);
				if (!name_rva)
					return nullptr;

				char temp[0x400];
				read(proc, roblox_base + name_rva + 0x10, temp, 0x400);

				std::string vftable_name = temp;

				if (vftable_name.contains("Unregistered"))
					return nullptr;

				if (cached_rva_offset == 0)
				{
					uint8_t headers[0x1000];
					read(proc, roblox_base, headers, sizeof(headers));

					PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)headers;
					PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(headers + dos->e_lfanew);

					uintptr_t size = nt->OptionalHeader.SizeOfImage;
					for (int i = 0x8; i < 0x100; i += 8)
					{
						if ((read<uintptr_t>(proc, getset + i) - roblox_base) < size)
						{
							cached_rva_offset = i;
							break;
						}
					}
				}

				if (vftable_name.contains("FFlag"))
				{
					FVarDescriptorBool* descriptor = new FVarDescriptorBool;

					descriptor->type = fvar_bool;
					descriptor->rva = read<uintptr_t>(proc, getset + cached_rva_offset) - roblox_base;

					write(proc, getset + cached_rva_offset - 0x10, read<uint8_t>(proc, getset + cached_rva_offset - 0x10) & ~2);

					return descriptor;
				}
				else if (vftable_name.contains("int") || vftable_name.contains("@H@"))
				{
					FVarDescriptorInt* descriptor = new FVarDescriptorInt;

					descriptor->type = fvar_int;
					descriptor->rva = read<uintptr_t>(proc, getset + cached_rva_offset) - roblox_base;

					write(proc, getset + cached_rva_offset - 0x10, read<uint8_t>(proc, getset + cached_rva_offset - 0x10) & ~2);

					return descriptor;
				}
				else if (vftable_name.contains("basic_string"))
				{
					FVarDescriptorString* descriptor = new FVarDescriptorString;

					descriptor->type = fvar_string;
					descriptor->rva = read<uintptr_t>(proc, getset + cached_rva_offset) - roblox_base;

					write(proc, getset + cached_rva_offset - 0x10, read<uint8_t>(proc, getset + cached_rva_offset - 0x10) & ~2);

					return descriptor;
				}
				else if (vftable_name.contains("Channel"))
				{
					FVarDescriptorLog* descriptor = new FVarDescriptorLog;

					descriptor->type = fvar_log;
					descriptor->rva = read<uintptr_t>(proc, getset + cached_rva_offset) - roblox_base;

					write(proc, getset + cached_rva_offset - 0x10, read<uint8_t>(proc, getset + cached_rva_offset - 0x10) & ~2);

					return descriptor;
				}

				return nullptr;
			}
		}

		if (entry == end) 
			return 0;

		entry = *(uintptr_t*)(entry_data + 0x8);
	}

	free(buffer);
	return nullptr;
}

std::vector<HANDLE> roblox_processes = {};
void refresh_roblox_processes()
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe;
	memset(&pe, 0, sizeof(pe));
	pe.dwSize = sizeof(pe);

	Process32First(snap, &pe);

	do
	{
		if (!strcmp(pe.szExeFile, "RobloxPlayerBeta.exe"))
			roblox_processes.push_back(OpenProcess(PROCESS_ALL_ACCESS, 0, pe.th32ProcessID));
	} while (Process32Next(snap, &pe));

	CloseHandle(snap);
}

void close_roblox_processes()
{
	for (HANDLE proc : roblox_processes)
		CloseHandle(proc);
	roblox_processes.clear();
}

void set_fvariable_for_all_processes(std::string fvar, std::string value)
{
	for (HANDLE proc : roblox_processes)
	{
		FVarDescriptor* descriptor = lookup_entry(proc, get_fvar_container(proc), fvar);
		if (!descriptor)
		{
			printf("didnt set %s because not found/not supported\n", fvar.c_str());
			return;
		}
		if (!descriptor->set(proc, value))
		{
			delete descriptor;
			printf("didnt set %s because invalid value\n", fvar.c_str());
			return;
		}
		delete descriptor;
	}
}

std::string fix_fvar_name(std::string name)
{
	if (name.starts_with("FFlag"))
		return name.substr(5);
	else if (name.starts_with("DFFlag"))
		return name.substr(6);
	else if (name.starts_with("FInt"))
		return name.substr(4);
	else if (name.starts_with("DFInt"))
		return name.substr(5);
	else if (name.starts_with("FLog"))
		return name.substr(4);
	else if (name.starts_with("DFLog"))
		return name.substr(5);
	else if (name.starts_with("FString"))
		return name.substr(7);
	else if (name.starts_with("DFString"))
		return name.substr(8);
	return name;
}

int main(int argc, const char** argv)
{
	if (argc == 2)
	{
		rapidjson::Document document;

		std::string path = argv[1];
		if (path.starts_with('"') && path.ends_with('"'))
			path = path.substr(1, path.size() - 2);

		FILE* file = nullptr;
		fopen_s(&file, path.c_str(), "r");
		if (!file)
		{
			printf("file not found: %s\n", path.c_str());
			system("pause");
			return 1;
		}

		fseek(file, 0, SEEK_END);
		uint32_t size = ftell(file);
		fseek(file, 0, SEEK_SET);
		
		char* buffer = (char*)malloc(size);
		rapidjson::FileReadStream file_stream(file, buffer, size);

		document.ParseStream(file_stream);

		free(buffer);

		if (document.HasParseError())
		{
			printf("json parsing error: %s\n", rapidjson::GetParseError_En(document.GetParseError()));
			system("pause");
			return 1;
		}

		printf("watching for roblox processes\n");

		while (true)
		{
			refresh_roblox_processes();
			for (rapidjson::Value::ConstMemberIterator entry = document.MemberBegin(); entry != document.MemberEnd(); entry++)
				set_fvariable_for_all_processes(fix_fvar_name(entry->name.GetString()), entry->value.GetString());

			close_roblox_processes();

			Sleep(10000);
		}

		return 0;
	}

	while (true)
	{
		printf("enter fvariable name: ");
		std::string fvar;
		std::cin >> fvar;

		printf("enter value: ");
		std::string value;
		std::cin >> value;
		
		refresh_roblox_processes();
		set_fvariable_for_all_processes(fix_fvar_name(fvar), value);
		close_roblox_processes();
	}
}