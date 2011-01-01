/****************************************************************************
 * Copyright (C) 2011 by th3mis [the.th3mis@gmail.com]                      *
 *                                                                          *
 * This file is part of Portable Executable Resource Editor (PERE)          *
 ****************************************************************************/

#if !defined __PERE_H__

#define __PERE_H__
#define RE_UNICODE_NULL_SIZE   2
#define RE_NAME_BIT            0x80000000

#define SIZE_OF_ARRAY(x) sizeof(x) / sizeof(*x)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

typedef unsigned char byte, BYTE;
typedef unsigned short int word, WORD, unicode_t;
typedef unsigned int dword, DWORD;
typedef BYTE *PBYTE, *LPBYTE;
typedef DWORD *PDWORD, *LPDWORD;
typedef WORD *PWORD, *LPWORD;

enum RE_Error_Types {
    RE_FAIL = 0,
    RE_SUCCESS = 1,
    RE_RESOURCE_ALREADY_EXIST,
    RE_RESOURCE_EXIST,
    RE_RESOURCE_NOT_EXIST,
};

enum ResourceType {
    RT_CURSOR         = 1,
    RT_BITMAP         = 2,
    RT_ICON           = 3,
    RT_MENU           = 4,
    RT_DIALOG         = 5,
    RT_STRING         = 6,
    RT_FONTDIR        = 7,
    RT_FONT           = 8,
    RT_ACCELERATOR    = 9,
    RT_RCDATA         = 10,
    RT_MESSAGETABLE   = 11,
    RT_GROUP_CURSOR   = 12,
    RT_GROUP_ICON     = 14,
    RT_VERSION        = 16,
    RT_DLGINCLUDE     = 17,
    RT_PLUGPLAY       = 19,
    RT_VXD            = 20,
    RT_ANICURSOR      = 21,
    RT_ANIICON        = 22,
    RT_MANIFEST       = 24,
};

enum RT_LANGUAGE_ARRAY {
    LANG_ENGLISH = 0x0409,
    LANG_RUSSIAN = 0x0419,
};

struct ResourceToolResult {
    PBYTE Offset;
    DWORD Size;
};

typedef struct _PESection {
    char Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD PhysicalSize;
    DWORD PhysicalOffset;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} PESection, *pPESection;

struct _ResourceItems {
    DWORD iResourceType;
    unicode_t *wResourceType;
    DWORD IncludeItemCount;
    DWORD NameCount;
    DWORD IdCount;
    struct _ResourceItem *ResourceItem;
};

typedef struct _ResourceInfo {
    DWORD iName;
    unicode_t *cName;
    DWORD Language;
    DWORD CodePage;
    DWORD Reserved;
    DWORD RVA_Offset;   // Virtual Address
    PBYTE Buffer;       // Direct pointer
    DWORD RawSize;
} ResourceInfo, *pResourceInfo;

struct _GetResourceType {
    DWORD iName;
    unicode_t *cName;
};

typedef struct _PE_Header {
    DWORD Offset_DataDirectories;
    DWORD Header;
    WORD  SectionNum;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    DWORD SizeOfOptionalHeaders;
    DWORD ResourceTable;
    DWORD ResourceTableOffset;
    DWORD ResourceTableNum;
    DWORD SizeOfHeaders;
} PE_Header, *pPE_Header;

class PERE {
public:
    DWORD TimeDateStamp = 0, CodePage = 0;
    WORD MajorVersion = 0, MinorVersion = 0;
    bool NeedPEHeaderFix = true, SafeMode, padding = false;

    PERE(void) {};

    /** Add resource from file on filesystem
     *
     *  @param FilePath - path to resource file on filesystem
     *  @param iType    - numeric name of resource type
     *  @param cType    - pointer to char array of resource type
     *  @param iName    - numeric name of resource name
     *  @param cName    - pointer to char array of resource name
     *  @param Lang     - language identificator
     *
     *  @return status RE_SUCCESS or RE_FAIL
     */
    int AddResourceFromFile(char *FilePath, DWORD iType, char *cType,
                            DWORD iName, char *cName, DWORD Lang);

    /** Add resource from buffer
     *
     *  @param Buffer - pointer to data
     *  @param Size   - size of data
     *  @param iType  - numeric name of resource type
     *  @param cType  - pointer to char array of resource type
     *  @param iName  - numeric name of resource name
     *  @param cName  - pointer to char array of resource name
     *  @param Lang   - language identificator
     *
     *  @return status RE_SUCCESS or RE_FAIL
     */
    int AddResourceFromMemory(PBYTE Buffer, DWORD Size, DWORD iType, char *cType,
                              DWORD iName, char *cName, DWORD Lang);

    /** Parse resources from `res` file and write it into resource table of
     *  opened file.
     *
     *  @param path to `res` file on filesystem
     *
     *  @return status RE_SUCCESS or RE_FAIL
     */
    int LoadResourceFromResFile(char *ResFilePath);

    /** Save parsed resources to `res` file on filesystem.
     *
     *  @param ResFilePath - path to `res` file on filesystem
     *
     *  @return status RE_SUCCESS or RE_FAIL
     */
    int SaveResourceToResFile(char *ResFilePath);

    /** Find resources in opened file
     *
     *  @param iType - numeric name of resource type
     *  @param cType - pointer to char array of resource type
     *  @param iName - numeric name of resource name
     *  @param cName - pointer to char array of resource name
     *  @param pResourceInfo ResInfo - pointer to structure, if resource will be
     *  found, function will save to it structure pointer and size to resources.
     *
     *  @return status RE_SUCCESS or RE_FAIL
     */
    int FindResource(DWORD iType, char *cType, DWORD iName, char *cName,
                     pResourceInfo ResInfo);

    int GetResourceCount(int NameIndex, int LanguageIndex);

    int GetResourceByIndex(DWORD TypeIndex, int NameIndex,
                           int LanguageIndex, pResourceInfo ResInfo);

    int BeginUpdateResource(char *FilePath, bool DeleteTable);

    int BeginUpdateResourceInMemory(PBYTE *Pointer, PDWORD Size, bool DeleteTable);

    int UpdateResource(DWORD iResourceType, char *cResourceType,
                       DWORD iResourceName, char *cResourceName,
                       DWORD Lang, PBYTE DataPointer, DWORD DataSize);

    int EndUpdateResource(void);

private:
    FILE *FHandle;
    PBYTE VirtualFile = NULL;
    DWORD FileSize, OriginalFileSize;

    PE_Header PE;
    DWORD ResourceItemsNum, ResourceTableNum;
    struct _ResourceItems *ResourceItems;
    ResourceInfo GetResourceInfo_Result;
    struct _GetResourceType GetResourceType_Result;
    bool SaveOldTable, PE32, FileLoaded, NoAddData = false, RebuildTable;

    char *SavedFilePath;
    unicode_t cResourceType_tmp[256], cResourceName_tmp[256], *CharNameMemory;
    DWORD CharNameMemorySize = 0, CharNameMemoryPointer;
    PDWORD pSize;
    PBYTE *pPointer;

    void RaiseError(const char *message);

    int NameBitCheck(DWORD in);
    bool NameBitSet(PDWORD in);
    bool NameBitUnset(PDWORD in);

    int OpenFile(char *FilePath);
    void FillAlign(PBYTE ptr, DWORD size);
    void CloseFile(void);

    DWORD AlignValue(DWORD Value, DWORD Alignment);
    DWORD RVA2RAW(DWORD RVA);
    DWORD AllocateResourceTable(DWORD Size, PESection &ResourceSection);
    WORD GetResourceNumber(DWORD iResourceType, unicode_t *cResourceType);
    int ReadPEHeader(void);
    int RaiseSizeOfHeaders(void);

    void GetResourceInfo(DWORD iResourceType, unicode_t *cResourceType, DWORD Index);
    int GetResourceType(DWORD Num);
    void SaveMemoryToFile(char *FilePath, void *Buffer, DWORD Size);
    void AddString(unicode_t **Out, unicode_t *In);
    void SortResource(void);
    void InitGlobalVar(void);

    int CreateResourceTable(bool RebuildTable);

    int AddResource(DWORD iResourceType, unicode_t *cResourceType,
                    DWORD iResourceName, unicode_t *cResourceName,
                    DWORD Language, PBYTE DataPointer, DWORD DataSize);

    int UnicodeLen(unicode_t *str);
    int UnicodeCmp(unicode_t *str1, unicode_t *str2);
    int UnicodeCpy(unicode_t *str1, unicode_t *str2);
    unicode_t* AsciiToUnicode(char *in);
};
#endif
