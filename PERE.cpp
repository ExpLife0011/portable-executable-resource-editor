/****************************************************************************
 * Copyright (C) 2011 by th3mis [the.th3mis@gmail.com]                      *
 *                                                                          *
 * This file is part of Portable Executable Resource Editor (PERE)          *
 ****************************************************************************/

#include "PERE.h"

typedef struct _ResourceDirectory {
    DWORD Flags;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    WORD NumOfNameEntry;
    WORD NumOfIdEntry;
} ResourceDirectory, *pResourceDirectory;

typedef struct _ResourceDirectoryEntry {
    DWORD Name;
    DWORD OffsetToData;
} ResourceDirectoryEntry, *pResourceDirectoryEntry;

typedef struct _ResourceDataEntry {
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
} ResourceDataEntry, *pResourceDataEntry;

typedef struct _ResourceItem {
    DWORD iResourceName;
    unicode_t *wResourceName;
    DWORD Language;
    PBYTE DataPointer;
    DWORD DataSize;
    DWORD AlignSize;
} ResourceItem, *pResourceItem;

void PERE::RaiseError(const char *message)
{
    printf("%s", message);
    getchar();
    exit(-1);
}

int PERE::NameBitCheck(DWORD in)
{
    return (in > RE_NAME_BIT) ? 1 : 0;
}

bool PERE::NameBitSet(PDWORD in)
{
    if (NameBitCheck(*in) == 1)
        return false;

    *in += RE_NAME_BIT;

    return true;
}

bool PERE::NameBitUnset(PDWORD in)
{
    if (NameBitCheck(*in) == 0)
        return false;

    *in -= RE_NAME_BIT;
    return true;
}

int PERE::UnicodeLen(unicode_t *str)
{
    if (str == NULL)
        return 0;

    int size = 0;

    while (str[size] != 0x0000) {
        size++;
        if (size > 256)
            RaiseError("probably bad unicode string!\n");
    }

    return size;
}

int PERE::UnicodeCmp(unicode_t *str1, unicode_t *str2)
{
    int result = 0, pos = 0;

    if (str1 == NULL || str2 == NULL) return -1;

    while (str1[pos] != 0x0000 || str1[pos] != 0x0000) {
        if (str1[pos] == str2[pos]) result =  0;
        if (str1[pos]  > str2[pos]) result =  1;
        if (str1[pos]  < str2[pos]) result = -1;
        pos ++;

        if (result != 0)
            return result;
    }

    return result;
}

int PERE::UnicodeCpy(unicode_t *str1, unicode_t *str2)
{
    memcpy(str1, str2, UnicodeLen(str2) * 2);
    return RE_SUCCESS;
}

unicode_t* PERE::AsciiToUnicode(char *in)
{
    unicode_t *result = (unicode_t*) calloc(strlen(in) + 1, sizeof(unicode_t));

    for (DWORD i = 0; i < strlen(in); i++)
        result[i] = in[i];

    return result;
}

int PERE::OpenFile(char *FilePath)
{
    SavedFilePath = FilePath;

    FHandle = fopen(FilePath, "rb+");
    if (FHandle == NULL)
        return RE_FAIL;

    fseek(FHandle, 0, SEEK_END);
    FileSize = ftell(FHandle);
    OriginalFileSize = FileSize;
    fseek(FHandle, 0, SEEK_SET);
    VirtualFile = (PBYTE) malloc(FileSize);
    fread(VirtualFile, 1, FileSize, FHandle);

    return (*(PWORD) &VirtualFile[0] == 0x5A4D) ? RE_SUCCESS : RE_FAIL;
}

void PERE::CloseFile(void)
{
    /* if no changes */
    if (ResourceItemsNum == 0) {
        fclose(FHandle);
        return;
    }

    if (FileSize >= OriginalFileSize) {
        fseek(FHandle, 0, SEEK_SET);
        fwrite(VirtualFile, 1, FileSize, FHandle);
        fclose(FHandle);
        return;
    }

    fclose(FHandle);
    remove(SavedFilePath);
    FHandle = fopen(SavedFilePath, "wb+");
    fwrite(VirtualFile, 1, FileSize, FHandle);
    fclose(FHandle);
}

DWORD PERE::AlignValue(DWORD Value, DWORD Alignment)
{
    return (Value % Alignment != 0) ? Value += Alignment - (Value % Alignment) : Value;
}

DWORD PERE::RVA2RAW(DWORD RVA)
{
    PESection tmpSection;

    if (RVA == 0)
        return RE_FAIL;

    for (WORD i = 0; i < PE.SectionNum; i++) {
        memcpy(&tmpSection,
               &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (i * 0x28)],
               sizeof(PESection));

        tmpSection.VirtualSize = AlignValue(tmpSection.VirtualSize, PE.SectionAlignment);
        if (RVA >= tmpSection.VirtualAddress && RVA < tmpSection.VirtualAddress + tmpSection.VirtualSize) {
            if (tmpSection.PhysicalOffset + (RVA - tmpSection.VirtualAddress) > FileSize)
                RaiseError("RVA2RAW Error, RAW is too big! Exit!\n");

            return tmpSection.PhysicalOffset + (RVA - tmpSection.VirtualAddress);
        }
    }

    RaiseError("RVA2RAW Error!\n");
    return RE_FAIL;
}

int PERE::ReadPEHeader(void)
{
    if (VirtualFile == NULL)
        return RE_FAIL;

    PE.Header = *(PDWORD) &VirtualFile[0x3C];
    PE.SectionAlignment = *(PDWORD) &VirtualFile[PE.Header + 0x38];
    PE.FileAlignment = *(PDWORD) &VirtualFile[PE.Header + 0x3C];
    PE.SizeOfHeaders = *(PDWORD) &VirtualFile[PE.Header + 0x54];
    WORD MagicNumber = *(PWORD) &VirtualFile[PE.Header + 0x18];

    /* PE32 (x86) */
    if (MagicNumber == 0x010B) {
        PE32 = true;
        PE.ResourceTable = *(PDWORD) &VirtualFile[PE.Header + 0x88];
    }

    /* PE32+ (x64) */
    if (MagicNumber == 0x020B) {
        PE32 = false;
        PE.ResourceTable = *(PDWORD) &VirtualFile[PE.Header + 0x98];
    }

    PE.Offset_DataDirectories = (PE32) ? PE.Header + 0x78 : PE.Header + 0x88;

    PE.SizeOfOptionalHeaders = *(PWORD) &VirtualFile[PE.Header + 0x14];
    PE.SectionNum = *(PWORD) &VirtualFile[PE.Header + 0x06];
    PE.ResourceTableOffset = PE.ResourceTable;

    if (PE.ResourceTable != 0) {
        PE.ResourceTable = RVA2RAW(PE.ResourceTable);
        /* count of ids */
        PE.ResourceTableNum = *(PWORD) &VirtualFile[PE.ResourceTable + sizeof(ResourceDirectory) - 2];
        /* count of strings */
        PE.ResourceTableNum += *(PWORD) &VirtualFile[PE.ResourceTable + sizeof(ResourceDirectory) - 4];
    } else {
        PE.ResourceTableNum = 0;
    }

    return RE_SUCCESS;
}

int PERE::RaiseSizeOfHeaders(void)
{
    DWORD i, NewSizeOfHeaders;
    PESection tmpSection;

    memcpy(&tmpSection,
           &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders],
           sizeof(tmpSection));

    /* increasing PE.SizeOfHeaders unnecessary */
    if (tmpSection.PhysicalOffset >= PE.Header + PE.SizeOfOptionalHeaders + 0x28 * (PE.SectionNum + 1) + 0x18)
        return RE_SUCCESS;

    FileSize += PE.FileAlignment;
    VirtualFile = (PBYTE) realloc(VirtualFile, FileSize);

    memcpy(&VirtualFile[tmpSection.PhysicalOffset + PE.FileAlignment],
           &VirtualFile[tmpSection.PhysicalOffset],
           FileSize - (tmpSection.PhysicalOffset + PE.FileAlignment));

    /* zeroes memory */
    for (i = 0; i < PE.FileAlignment; i++)
        VirtualFile[tmpSection.PhysicalOffset - tmpSection.PhysicalSize + PE.FileAlignment + i] = 0x00;

    /* fix section offsets */
    for (i = 0; i < PE.SectionNum; i++) {
        memcpy(&tmpSection,
               &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (i * 0x28)],
               sizeof(tmpSection));

        tmpSection.PhysicalOffset += PE.FileAlignment;

        memcpy(&VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (i * 0x28)],
               &tmpSection,
               sizeof(tmpSection));

        if (i == 0)
            NewSizeOfHeaders = tmpSection.PhysicalOffset;
    }

    /* Change PE.SizeOfHeaders in PE header */
    *(PDWORD) &VirtualFile[PE.Header + 0x18 + 0x3C] = NewSizeOfHeaders;

    return RE_SUCCESS;
}

/* File the end of resource section word "PADDINGXX" */
void PERE::FillAlign(PBYTE ptr, dword size)
{
    const char pad[] = "PADDINGXX";
    DWORD i, pos = 0;

    for (i = 0; i < size / 9; i++) {
        memcpy(&ptr[pos], &pad[0], 9);
        pos += 9;
    }

    memcpy(&ptr[pos], &pad[0], size % 9);
}

DWORD PERE::AllocateResourceTable(DWORD size, PESection &ResourceSection)
{
    DWORD j, NewPhysicalSize, CurrentSection, OldVirtualSize, sizeOfInitData = 0;
    PESection LastSection;
    int DeltaSize;
    bool DontResize, CreateNewSection = false;

    /* find resource section */
    for (int i = 0; i < PE.SectionNum; i++) {
        memcpy(&ResourceSection,
               &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (i*sizeof(ResourceSection))],
               sizeof(ResourceSection));

        /* calculate size of initialized data for future fix */
        if ((ResourceSection.Characteristics & 0x00000040) > 0 &&
             ResourceSection.VirtualAddress != PE.ResourceTableOffset)
            sizeOfInitData += ResourceSection.PhysicalSize;

        if (SafeMode == true &&
            i + 1 != PE.SectionNum &&
            ResourceSection.VirtualAddress == PE.ResourceTableOffset) {
            CreateNewSection = false;

            memcpy(&LastSection,
                   &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + ((PE.SectionNum - 1) * 0x28)],
                   sizeof(LastSection));

            if (strcmp(LastSection.Name, ".reloc") != 0)
                CreateNewSection = true;
        }

        /* create resources section if no exists */
        if ((PE.SectionNum == i + 1 && ResourceSection.VirtualAddress != PE.ResourceTableOffset) ||
            (CreateNewSection == true && size > ResourceSection.PhysicalSize)) {

            RaiseSizeOfHeaders();

            /* read last PE section */
            memcpy(&LastSection,
                   &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + ((PE.SectionNum - 1) * 0x28)],
                   sizeof(LastSection));

            strcpy(ResourceSection.Name, ".rsrc");
            ResourceSection.VirtualSize = size;
            ResourceSection.VirtualAddress = AlignValue(LastSection.VirtualAddress + LastSection.VirtualSize, PE.SectionAlignment);
            ResourceSection.PhysicalSize = AlignValue(size, PE.FileAlignment);

            /* if last section have zero size */
            CurrentSection = PE.SectionNum;
            if (LastSection.PhysicalSize == 0)
                while (LastSection.PhysicalSize == 0 && CurrentSection != 0) {
                    memcpy(&LastSection,
                           &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + ((CurrentSection - 1) * 0x28)],
                           sizeof(LastSection));
                    CurrentSection--;
                }

            ResourceSection.PhysicalOffset = LastSection.PhysicalOffset + LastSection.PhysicalSize;
            ResourceSection.PointerToRelocations = 0;
            ResourceSection.PointerToLinenumbers = 0;
            ResourceSection.NumberOfRelocations = 0;
            ResourceSection.NumberOfLinenumbers = 0;
            ResourceSection.Characteristics = 0x40000040;

            /* write section description */
            memcpy(&VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (PE.SectionNum * 0x28)],
                   &ResourceSection,
                   sizeof(LastSection));
            *(PWORD) &VirtualFile[PE.Header + 0x06] = ++PE.SectionNum;

            /* increase buffer */
            FileSize += ResourceSection.PhysicalSize;
            VirtualFile = (PBYTE) realloc(VirtualFile, FileSize);

            /* change PE header - pointer to resources */
            *(PDWORD) &VirtualFile[PE.Offset_DataDirectories + 0x10] = ResourceSection.VirtualAddress;
            *(PDWORD) &VirtualFile[PE.Offset_DataDirectories + 0x14] = ResourceSection.VirtualSize;

            /* SizeOfImage */
            *(PDWORD) &VirtualFile[PE.Header + 0x50] = AlignValue(ResourceSection.VirtualAddress + \
                                                                  ResourceSection.VirtualSize, PE.SectionAlignment);

            if (NeedPEHeaderFix == true) {
                sizeOfInitData += AlignValue(ResourceSection.VirtualSize, PE.FileAlignment);
                *(PDWORD) &VirtualFile[PE.Header + 0x20] = sizeOfInitData;
            }

            if (padding) {
                FillAlign(&VirtualFile[ResourceSection.PhysicalOffset + size], ResourceSection.PhysicalSize - size);
            } else {
                memset(&VirtualFile[ResourceSection.PhysicalOffset + size], 0x00, ResourceSection.PhysicalSize - size);
            }

            return ResourceSection.PhysicalOffset;
        }

        /* if current section is section of resources */
        if (ResourceSection.VirtualAddress == PE.ResourceTableOffset) {
            DontResize = (CreateNewSection == true && size <= ResourceSection.PhysicalSize) ? true : false;

            /* calculate new sizes */
            OldVirtualSize = ResourceSection.VirtualSize;
            NewPhysicalSize = AlignValue(size, PE.FileAlignment);
            DeltaSize = (!DontResize) ? NewPhysicalSize - AlignValue(ResourceSection.PhysicalSize, PE.FileAlignment) : 0;
            FileSize += DeltaSize;

            /* if size became larger then increase buffer */
            if (DeltaSize > 0)
                VirtualFile = (PBYTE) realloc(VirtualFile, FileSize);

            /* fix PE Entry Point */
            if (*(PDWORD) &VirtualFile[PE.Header + 0x28] >= ResourceSection.VirtualAddress) {
                *(PDWORD) &VirtualFile[PE.Header + 0x28] += AlignValue(size, PE.SectionAlignment) - AlignValue(OldVirtualSize, PE.SectionAlignment);
            }

            ResourceSection.VirtualSize = size;
            if (!DontResize) ResourceSection.PhysicalSize = NewPhysicalSize;
            memcpy(&VirtualFile[PE.Header + PE.SizeOfOptionalHeaders + 0x18 + (i * 0x28)],
                   &ResourceSection,
                   sizeof(ResourceSection));

            /* move data of the lower sections below if necessary */
            if (!DontResize) {
                memcpy(&VirtualFile[ResourceSection.PhysicalOffset + ResourceSection.PhysicalSize],
                       &VirtualFile[ResourceSection.PhysicalOffset + (ResourceSection.PhysicalSize - DeltaSize)],
                       (FileSize - DeltaSize) - (ResourceSection.PhysicalOffset + (NewPhysicalSize - DeltaSize)));
            }

            if (DeltaSize < 0)
                VirtualFile = (PBYTE) realloc(VirtualFile, FileSize);

            /* fix virtual and physical offset of sections */
            if (i != PE.SectionNum - 1) for (j = i + 1; j < PE.SectionNum; j++) {
                    memcpy(&LastSection,
                           &VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (j * 0x28)],
                           sizeof(LastSection));

                    LastSection.VirtualAddress -= AlignValue(OldVirtualSize, PE.SectionAlignment);
                    LastSection.VirtualAddress += AlignValue(ResourceSection.VirtualSize, PE.SectionAlignment);
                    LastSection.PhysicalOffset += DeltaSize;

                    /* relocation section */
                    if (strcmp(LastSection.Name, ".reloc") == 0) {
                        /* Relocation Table Address */
                        *(PDWORD) &VirtualFile[PE.Offset_DataDirectories + 0x28] = LastSection.VirtualAddress; // Relocation Table Address
                    }

                    memcpy(&VirtualFile[PE.Header + 0x18 + PE.SizeOfOptionalHeaders + (j * 0x28)],
                           &LastSection,
                           sizeof(LastSection));

                    *(PDWORD) &VirtualFile[PE.Header + 0x50] = AlignValue(LastSection.VirtualAddress + LastSection.VirtualSize, PE.SectionAlignment); // size of Image
                }
            else {
                *(PDWORD) &VirtualFile[PE.Header + 0x50] = AlignValue(ResourceSection.VirtualAddress + ResourceSection.VirtualSize, PE.SectionAlignment);
            }

            /* resource table size */
            *(PDWORD) &VirtualFile[PE.Offset_DataDirectories + 0x14] = size;

            if (NeedPEHeaderFix == true) {
                sizeOfInitData += AlignValue(size, PE.FileAlignment);
                *(PDWORD) &VirtualFile[PE.Header + 0x20] = sizeOfInitData;
            }

            if (padding) {
                FillAlign(&VirtualFile[ResourceSection.PhysicalOffset + size],
                          ResourceSection.PhysicalSize - size);
            } else {
                memset(&VirtualFile[ResourceSection.PhysicalOffset + size],
                       0x00,
                       ResourceSection.PhysicalSize - size);
            }

            return ResourceSection.PhysicalOffset;
        }
    }

    return RE_SUCCESS;
}

WORD PERE::GetResourceNumber(DWORD iResourceType, unicode_t *cResourceType)
{
    for (DWORD i = 0; i < PE.ResourceTableNum; i++) {
        DWORD offset = PE.ResourceTable + \
                       sizeof(ResourceDirectory) + \
                       sizeof(struct _ResourceDirectoryEntry);

        if (*(PDWORD) &VirtualFile[offset*i] != iResourceType)
            continue;

        offset = *(PDWORD) &VirtualFile[offset * i + 4];
        NameBitUnset(&offset);
        WORD ResourceCount = *(PWORD) &VirtualFile[PE.ResourceTable + offset + sizeof(ResourceDirectory) - 2];

        ResourceCount += *(PWORD) &VirtualFile[PE.ResourceTable + offset + sizeof(ResourceDirectory) - 4];
        return ResourceCount;
    }

    return RE_FAIL;
}

void PERE::GetResourceInfo(DWORD iResourceType, unicode_t *cResourceType, DWORD Index)
{
    DWORD Offset, i;
    WORD WStringLen;
    ResourceDataEntry ResourceDataEntry;

    GetResourceInfo_Result.Buffer = 0;
    GetResourceInfo_Result.RawSize = 0;

    DWORD RD_Tail = PE.ResourceTable + sizeof(ResourceDirectory);

    for (i = 0; i < PE.ResourceTableNum; i++) {
        if (*(PDWORD) &VirtualFile[RD_Tail + sizeof(struct _ResourceDirectoryEntry)*i] != iResourceType)
            continue;

        Offset = *(PDWORD) &VirtualFile[RD_Tail + sizeof(struct _ResourceDirectoryEntry) * i + 4];
        NameBitUnset(&Offset);

        /* get resource id */
        GetResourceInfo_Result.iName = *(PDWORD) &VirtualFile[RD_Tail + Offset + Index * 8 + 0];

        /* if 31 bit is set then it is pointer to UNICODE name of resource */
        if (NameBitUnset(&GetResourceInfo_Result.iName) == 1) {
            WStringLen = *(PWORD) &VirtualFile[PE.ResourceTable + GetResourceInfo_Result.iName];

            memcpy(&cResourceName_tmp[0],
                   &VirtualFile[2 + PE.ResourceTable + GetResourceInfo_Result.iName],
                   WStringLen * 2);

            cResourceName_tmp[WStringLen] = 0x0000;
            GetResourceInfo_Result.cName = &cResourceName_tmp[0];
        } else {
            GetResourceInfo_Result.cName = NULL;
        }

        Offset = *(PDWORD) &VirtualFile[RD_Tail + Offset + Index * 8 + 4];

        NameBitUnset(&Offset);

        /* read resource language */
        GetResourceInfo_Result.Language = *(PDWORD) &VirtualFile[RD_Tail + Offset + 0];
        Offset = *(PDWORD) &VirtualFile[RD_Tail +  Offset + 4];

        /* offset and size of resource */
        memcpy(&ResourceDataEntry,
               &VirtualFile[PE.ResourceTable + Offset],
               sizeof(ResourceDataEntry));

        GetResourceInfo_Result.RVA_Offset = ResourceDataEntry.OffsetToData;
        GetResourceInfo_Result.Buffer = &VirtualFile[RVA2RAW(ResourceDataEntry.OffsetToData)];
        GetResourceInfo_Result.RawSize = ResourceDataEntry.Size;
        GetResourceInfo_Result.CodePage = ResourceDataEntry.CodePage;
        GetResourceInfo_Result.Reserved = ResourceDataEntry.Reserved;
        CodePage = ResourceDataEntry.CodePage;
    }
}

int PERE::GetResourceType(DWORD Num)
{
    int offset = PE.ResourceTable + sizeof(ResourceDirectory) + \
                 sizeof(struct _ResourceDirectoryEntry) * Num;

    GetResourceType_Result.iName = *(PDWORD) &VirtualFile[offset];

    /* pointer to UNICODE type of resource is using */
    if (NameBitUnset(&GetResourceType_Result.iName) == 1) {
        short int WStringLen = *(PWORD) &VirtualFile[PE.ResourceTable + GetResourceType_Result.iName];
        for (int i = 0; i < WStringLen; i++)
            cResourceType_tmp[i] = VirtualFile[PE.ResourceTable + GetResourceType_Result.iName + 2 + i * 2];

        cResourceType_tmp[WStringLen] = 0x0000;
        GetResourceType_Result.cName = &cResourceType_tmp[0];
        NameBitSet(&GetResourceType_Result.iName);
    } else {
        GetResourceType_Result.cName = NULL;
    }

    return RE_SUCCESS;
}

void PERE::SaveMemoryToFile(char *FilePath, void *Buffer, DWORD size)
{
    FILE *FHandle = fopen(FilePath, "wb");

    if (FHandle == NULL)
        RaiseError("SaveMemoryToFile::Open file error!\n");

    fwrite(Buffer, 1, size, FHandle);
    fclose(FHandle);
}

int PERE::CreateResourceTable(bool BuildNewTable)
{
    DWORD i, j, k, n, ResourceTableSize, RC_Size;
    ResourceDirectory ResourceDirectory;
    struct _ResourceDirectoryEntry ResourceDirectoryEntry;
    ResourceDataEntry ResourceDataEntry;
    PBYTE VirtualResourceTable;
    DWORD RT_Pointer, RN_Pointer = 0, RL_Pointer, RP_Pointer, RD_Pointer, RC_Pointer;
    WORD MT_NumOfNameEntry = 0, NumOfIdEntry = 0;
    PESection ResourceSection;

    /* free memory */
    if (!BuildNewTable) {
        for (i = 0; i < ResourceItemsNum; i++) {
            for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
                free(ResourceItems[i].ResourceItem[j].DataPointer);

                if (j == ResourceItems[i].IncludeItemCount - 1)
                    free(ResourceItems[i].ResourceItem);
            }
        }

        if (ResourceItemsNum != 0)
            free(ResourceItems);

        if (CharNameMemorySize != 0)
            free(CharNameMemory);

        return RE_SUCCESS;
    }

    /* resource table is empty */
    if (ResourceItemsNum == 0)
        return RE_FAIL;

    SortResource();

    /* calculate count of names and ids */
    for (i = 0; i < ResourceItemsNum; i++)
        (ResourceItems[i].wResourceType == NULL) ? NumOfIdEntry++ : MT_NumOfNameEntry++;

    /* make ResourceDirectory structure */
    ResourceDirectory.Flags = 0;
    ResourceDirectory.TimeDateStamp = TimeDateStamp;
    ResourceDirectory.MajorVersion = MajorVersion;
    ResourceDirectory.MinorVersion = MinorVersion;
    ResourceDirectory.NumOfNameEntry = MT_NumOfNameEntry;
    ResourceDirectory.NumOfIdEntry = NumOfIdEntry;

    /* calculate size of resource table */
    ResourceTableSize = sizeof(ResourceDirectory);
    for (i = 0; i < ResourceItemsNum; i++) {
        ResourceTableSize += sizeof(struct _ResourceDirectoryEntry);
        ResourceTableSize += sizeof(ResourceDirectory);

        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            ResourceTableSize += sizeof(struct _ResourceDirectoryEntry);
            ResourceTableSize += sizeof(ResourceDirectory);

            ResourceTableSize += sizeof(struct _ResourceDirectoryEntry);
            ResourceTableSize += sizeof(ResourceDataEntry);
            ResourceTableSize += ResourceItems[i].ResourceItem[j].DataSize;
        }
    }

    /* calculate Resource Pointer Pointer */
    RP_Pointer = ResourceTableSize;
    for (i = 0; i < ResourceItemsNum; i++) {
        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            RP_Pointer -= sizeof(ResourceDataEntry);
            RP_Pointer -= ResourceItems[i].ResourceItem[j].DataSize;
        }
    }

    /* calculate Resource Data Pointer*/
    RD_Pointer = ResourceTableSize;
    for (i = 0; i < ResourceItemsNum; i++) for (j = 0; j < ResourceItems[i].IncludeItemCount; j++)
            RD_Pointer -= ResourceItems[i].ResourceItem[j].DataSize;

    /* calculate memory for strings */
    RC_Pointer = RD_Pointer;
    RC_Size = 0;
    for (i = 0; i < ResourceItemsNum; i++) {
        if (ResourceItems[i].wResourceType != NULL)
            RC_Size += UnicodeLen(ResourceItems[i].wResourceType) * 2 + RE_UNICODE_NULL_SIZE;

        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            if (ResourceItems[i].ResourceItem[j].wResourceName != NULL)
                RC_Size += UnicodeLen(ResourceItems[i].ResourceItem[j].wResourceName) * 2 + RE_UNICODE_NULL_SIZE;
        }
    }

    /* align reserved buffer by 4 (x86) | 8 (x64) */
    if (RC_Size != 0) RC_Size = (PE32 == true) ? AlignValue(RC_Size, 4) : AlignValue(RC_Size, 8);

    /* allocate space for strings */
    RD_Pointer += RC_Size;
    ResourceTableSize += RC_Size;
    ResourceTableSize = (PE32 == true) ? AlignValue(ResourceTableSize, 4) : AlignValue(ResourceTableSize, 8);

    VirtualResourceTable = (PBYTE) calloc(ResourceTableSize, sizeof(BYTE));
    memcpy(&VirtualResourceTable[0], &ResourceDirectory, sizeof(ResourceDirectory));

    AllocateResourceTable(ResourceTableSize, ResourceSection);

    /* RT_ICON - N */
    RL_Pointer = sizeof(ResourceDirectory) + sizeof(ResourceDirectoryEntry) * ResourceItemsNum;
    for (i = 0; i < ResourceItemsNum; i++) {
        RL_Pointer += sizeof(ResourceDirectory);
        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++)
            RL_Pointer += sizeof(ResourceDirectoryEntry);
    }
    RL_Pointer -= sizeof(ResourceDirectory) + sizeof(ResourceDirectoryEntry);

    /* format and write resource table */
    for (i = 0; i < ResourceItemsNum; i++) {
        RT_Pointer = sizeof(ResourceDirectory) + sizeof(ResourceDirectoryEntry) * i;
        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            RL_Pointer += sizeof(ResourceDirectory) + sizeof(ResourceDirectoryEntry);

            /* write ResourceDirectory */
            if (j == 0) {
                ResourceDirectory.Flags          = 0;
                ResourceDirectory.TimeDateStamp  = TimeDateStamp;
                ResourceDirectory.MajorVersion   = MajorVersion;
                ResourceDirectory.MinorVersion   = MinorVersion;
                ResourceDirectory.NumOfNameEntry = ResourceItems[i].NameCount;
                ResourceDirectory.NumOfIdEntry   = ResourceItems[i].IdCount;

                /* calculate pointer */
                RN_Pointer = sizeof(ResourceDirectory) + sizeof(ResourceDirectoryEntry) * ResourceItemsNum;
                for (n = 0; n < i; n++) {
                    RN_Pointer += sizeof(ResourceDirectory);
                    for (k = 0; k < ResourceItems[n].IncludeItemCount; k++)
                        RN_Pointer += sizeof(ResourceDirectoryEntry);
                }

                /* create ResourceDirectoryEntry */
                if (ResourceItems[i].wResourceType == NULL) {
                    ResourceDirectoryEntry.Name = ResourceItems[i].iResourceType;
                } else {
                    ResourceDirectoryEntry.Name = RE_NAME_BIT + RC_Pointer;
                    *(PWORD) &VirtualResourceTable[RC_Pointer] = UnicodeLen(ResourceItems[i].wResourceType);
                    RC_Pointer += RE_UNICODE_NULL_SIZE;
                    UnicodeCpy((unicode_t*) &VirtualResourceTable[RC_Pointer], ResourceItems[i].wResourceType);
                    RC_Pointer += UnicodeLen(ResourceItems[i].wResourceType) * 2;
                }

                ResourceDirectoryEntry.OffsetToData = RE_NAME_BIT + RN_Pointer;

                memcpy(&VirtualResourceTable[RT_Pointer],
                       &ResourceDirectoryEntry,
                       sizeof(ResourceDirectoryEntry));

                memcpy(&VirtualResourceTable[RN_Pointer],
                       &ResourceDirectory,
                       sizeof(ResourceDirectory));
            }

            /* resource name */
            if (ResourceItems[i].ResourceItem[j].wResourceName == NULL) {
                ResourceDirectoryEntry.Name = ResourceItems[i].ResourceItem[j].iResourceName;
            } else {
                /* pointer to unicode name of an resource  */
                ResourceDirectoryEntry.Name = RE_NAME_BIT + RC_Pointer;
                *(PWORD) &VirtualResourceTable[RC_Pointer] = UnicodeLen(ResourceItems[i].ResourceItem[j].wResourceName);
                RC_Pointer += RE_UNICODE_NULL_SIZE;
                UnicodeCpy((unicode_t*) &VirtualResourceTable[RC_Pointer], ResourceItems[i].ResourceItem[j].wResourceName);
                RC_Pointer += UnicodeLen(ResourceItems[i].ResourceItem[j].wResourceName) * 2;
            }

            ResourceDirectoryEntry.OffsetToData = RE_NAME_BIT + RL_Pointer;
            memcpy(&VirtualResourceTable[RN_Pointer + sizeof(ResourceDirectory) + sizeof(ResourceDirectoryEntry)*j],
                   &ResourceDirectoryEntry,
                   sizeof(ResourceDirectoryEntry));

            ResourceDirectory.Flags = 0;
            ResourceDirectory.TimeDateStamp = TimeDateStamp;
            ResourceDirectory.MajorVersion = MajorVersion;
            ResourceDirectory.MinorVersion = MinorVersion;
            ResourceDirectory.NumOfNameEntry = 0;
            ResourceDirectory.NumOfIdEntry = 1;
            memcpy(&VirtualResourceTable[RL_Pointer],
                   &ResourceDirectory,
                   sizeof(ResourceDirectory));

            ResourceDirectoryEntry.Name = ResourceItems[i].ResourceItem[j].Language;
            ResourceDirectoryEntry.OffsetToData = RP_Pointer;
            memcpy(&VirtualResourceTable[RL_Pointer + sizeof(ResourceDirectory)],
                   &ResourceDirectoryEntry,
                   sizeof(ResourceDirectoryEntry));

            /* format end structure */
            ResourceDataEntry.OffsetToData = ResourceSection.VirtualAddress + RD_Pointer;
            ResourceDataEntry.Size = ResourceItems[i].ResourceItem[j].DataSize - ResourceItems[i].ResourceItem[j].AlignSize;
            ResourceDataEntry.CodePage = CodePage;
            ResourceDataEntry.Reserved = 0;

            /* write formated structure */
            memcpy(&VirtualResourceTable[RP_Pointer],
                   &ResourceDataEntry,
                   sizeof(ResourceDataEntry));

            memcpy(&VirtualResourceTable[RD_Pointer],
                   ResourceItems[i].ResourceItem[j].DataPointer,
                   ResourceItems[i].ResourceItem[j].DataSize);

            /* change pointer to table tail and data */
            RP_Pointer += sizeof(ResourceDataEntry);
            RD_Pointer += ResourceItems[i].ResourceItem[j].DataSize;
        }
    }

    /* write generated resource table */
    memcpy(&VirtualFile[ResourceSection.PhysicalOffset],
           VirtualResourceTable,
           ResourceTableSize);

    /* free buffer */
    for (i = 0; i < ResourceItemsNum; i++) {
        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            free(ResourceItems[i].ResourceItem[j].DataPointer);

            if (j == ResourceItems[i].IncludeItemCount - 1)
                free(ResourceItems[i].ResourceItem);
        }
    }

    free(ResourceItems);
    free(VirtualResourceTable);

    if (CharNameMemorySize != 0)
        free(CharNameMemory);

    return RE_SUCCESS;
}

int PERE::SaveResourceToResFile(char *ResFilePath)
{
    PBYTE Data;
    DWORD i, j, Basepos, FileSize = 0x20, pos = 0x20;

    static const byte ResFileStub[] = {
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    /* file isn't open */
    if (VirtualFile == NULL)
        return RE_FAIL;

    /* calculate size of output file */
    for (i = 0; i < ResourceItemsNum; i++) {
        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            /* size of structure is 0x20 bytes */
            FileSize += 0x20;

            /* size of symbolic names */
            if (ResourceItems[i].wResourceType != NULL)
                FileSize += AlignValue(UnicodeLen(ResourceItems[i].wResourceType) * 2, 4);

            if (ResourceItems[i].ResourceItem[j].wResourceName != NULL)
                FileSize += AlignValue(UnicodeLen(ResourceItems[i].ResourceItem[j].wResourceName) * 2, 4);

            /* resource size */
            FileSize += AlignValue(ResourceItems[i].ResourceItem[j].DataSize, 4);
        }
    }

    if (FileSize == 0x20)
        return RE_FAIL;

    /* allocate buffer and write `res` stub */
    Data = (PBYTE) malloc(FileSize);
    memcpy(&Data[0], &ResFileStub[0], sizeof(ResFileStub));

    /* process resources table */
    for (i = 0; i < ResourceItemsNum; i++) for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            /* make header */
            Basepos = pos;
            *(PDWORD) &Data[pos + 0x00] = ResourceItems[i].ResourceItem[j].DataSize;
            // *(PDWORD) &Data[pos+0x04] = 0; // header size
            pos += 0x08;

            if (ResourceItems[i].wResourceType == NULL) {
                *(PWORD) &Data[pos + 0x00] = 0xFFFF;
                *(PWORD) &Data[pos + 0x02] = ResourceItems[i].iResourceType;
                pos += 4;
            } else {
                UnicodeCpy((unicode_t*) &Data[pos], ResourceItems[i].wResourceType);
                pos += AlignValue(UnicodeLen(ResourceItems[i].wResourceType) * 2, 4);
                *(PWORD) &Data[pos + 0x00] = 0x0000; // Null-terminated unicode string
                *(PWORD) &Data[pos + 0x00] = 0x0000; // ResourceItems[i].iResourceType;
                pos += 4;
            }

            if (ResourceItems[i].ResourceItem[j].wResourceName == NULL) {
                *(PWORD) &Data[pos + 0x00] = 0xFFFF; // cName
                *(PWORD) &Data[pos + 0x02] = ResourceItems[i].ResourceItem[j].iResourceName; // iName
                pos += 4;
            } else {
                UnicodeCpy((unicode_t*) &Data[pos], ResourceItems[i].ResourceItem[j].wResourceName);
                pos += AlignValue(UnicodeLen(ResourceItems[i].ResourceItem[j].wResourceName) * 2, 4);
                *(PWORD) &Data[pos + 0x00] = 0x0000; // Null-terminated unicode string
                *(PWORD) &Data[pos + 0x02] = 0x0000; // GetResourceInfo_Result.iName; // iType
                pos += 4;
            }

            *(PDWORD) &Data[pos + 0x00] = 0; // DataVersion
            *(PWORD)  &Data[pos + 0x04] = 0; // MemoryFlags
            *(PWORD)  &Data[pos + 0x06] = ResourceItems[i].ResourceItem[j].Language; // LanguageID
            *(PDWORD) &Data[pos + 0x08] = 0; // Version
            *(PDWORD) &Data[pos + 0x0C] = 0; // Characteristics
            pos += 0x10;

            /* size of header */
            *(PDWORD) &Data[Basepos + 0x04] = pos - Basepos;

            /* write resource content */
            memcpy(&Data[pos],
                   &ResourceItems[i].ResourceItem[j].DataPointer[0],
                   ResourceItems[i].ResourceItem[j].DataSize);

            pos += AlignValue(ResourceItems[i].ResourceItem[j].DataSize, 4);
        }

    /* save result to file */
    SaveMemoryToFile(ResFilePath, Data, FileSize);
    free(Data);
    return RE_SUCCESS;
}

int PERE::LoadResourceFromResFile(char *ResFilePath)
{
    FILE *FHandle;
    PBYTE File;
    DWORD FileSize, DataSize, pos = 0;
    WORD Lang, iType, iName, cType, cName;
    unicode_t _cType[512], _cName[512], *pType, *pName;

    if (VirtualFile == NULL)
        return RE_FAIL;

    /* read file content */
    FHandle = fopen(ResFilePath, "rb");
    if (FHandle == NULL)
        return RE_FAIL;

    fseek(FHandle, 0, SEEK_END);
    FileSize = ftell(FHandle);
    fseek(FHandle, 0, SEEK_SET);
    File = (PBYTE) malloc(FileSize);
    fread(File, 1, FileSize, FHandle);
    fclose(FHandle);

    /* process resource blocks */
    while (true) {
        DataSize = *(PDWORD) &File[pos + 0x00];
        cType = *(PWORD)  &File[pos + 0x08];
        pos += 0x08;

        /* if symbolic name */
        if (cType != 0xFFFF) {
            UnicodeCpy(&_cType[0], (unicode_t*) &File[pos]);
            _cType[UnicodeLen((unicode_t*) &File[pos]) + 1] = 0x0000;
            pType = _cType;
            pos += 2;
        } else {
            pType = NULL;
            pos += 2;
        }

        iType = *(PWORD) &File[pos + 0x00];
        cName = *(PWORD) &File[pos + 0x02];
        pos += 0x02;

        /* if symbolic name */
        if (cName != 0xFFFF) {
            UnicodeCpy(&_cType[0], (unicode_t*) &File[pos]);
            _cType[UnicodeLen((unicode_t*) &File[pos]) + 1] = 0x0000;
            pName = _cName;
            pos += 2;
        } else {
            pName = NULL;
            pos += 2;
        }

        iName       = *(PWORD)  &File[pos + 0x00];
        // *(PDWORD) &File[pos+0x02]; // DataVersion
        // *(PWORD)  &File[pos+0x06]; // MemoryFlags
        Lang        = *(PWORD)  &File[pos + 0x08]; // LanguageID
        // *(PDWORD) &File[pos+0x0A]; // Version
        // *(PDWORD) &File[pos+0x0E]; // Characteristics
        pos += 18;

        if (DataSize != 0)
            AddResource(iType, pType, iName, pName, Lang, &File[pos], DataSize);

        pos = AlignValue(pos + DataSize, 4);

        if (pos >= FileSize)
            return RE_SUCCESS;
    }

    return RE_SUCCESS;
}

void PERE::AddString(unicode_t **Out, unicode_t *In)
{
    int length;

    if (In == NULL) {
        *Out = NULL;
        return;
    }

    length = UnicodeLen(In) * 2;

    if (CharNameMemorySize == 0) {
        CharNameMemory = (unicode_t*) calloc(0x1000, sizeof(unicode_t));
        CharNameMemorySize = 0x1000;
        CharNameMemoryPointer = 0;
        memcpy(&CharNameMemory[CharNameMemoryPointer], &In[0], length);
        *Out = &CharNameMemory[CharNameMemoryPointer];
        CharNameMemoryPointer += length + RE_UNICODE_NULL_SIZE;
        return;
    }

    if (CharNameMemoryPointer + length + 1 > CharNameMemorySize) {
        CharNameMemorySize += 0x1000;
        CharNameMemory = (unicode_t*) realloc(CharNameMemory, CharNameMemorySize);
    }

    memcpy(&CharNameMemory[CharNameMemoryPointer], &In[0], length);
    *Out = &CharNameMemory[CharNameMemoryPointer];
    CharNameMemoryPointer += length + RE_UNICODE_NULL_SIZE;
}

int PERE::AddResource(DWORD iResourceType, unicode_t *wResourceType,
                      DWORD iResourceName, unicode_t *wResourceName,
                      DWORD Language, PBYTE DataPointer, DWORD DataSize)
{
    DWORD i, j, IncludeItemCount, AlignSize = 0;
    bool ResExists = false;

    /* rebuild resource table in file (have't any changes) */
    RebuildTable = true;

    if (DataSize == 0 || DataPointer == NULL)
        return RE_FAIL;

    if (UnicodeLen(wResourceType) == 0) wResourceType = NULL;
    if (UnicodeLen(wResourceName) == 0) wResourceName = NULL;

    /* aligning */
    if (PE32 == true) while (DataSize % 4 != 0) { AlignSize++; DataSize++; }
    if (PE32 != true) while (DataSize % 8 != 0) { AlignSize++; DataSize++; }

    /* create table if not exists */
    if (ResourceItemsNum == 0)
        ResourceItems = (struct _ResourceItems*) calloc(sizeof(struct _ResourceItems) * (ResourceItemsNum + 1), 1);

    /* find table with same resources type */
    for (i = 0; i < ResourceItemsNum; i++) {
        if (ResourceItems[i].iResourceType == iResourceType &&
            ResourceItems[i].wResourceType == wResourceType) {
            ResExists = true;
            break;
        }
    }

    /* find resource like that */
    if (ResExists == false && wResourceType != NULL) {
        for (i = 0; i < ResourceItemsNum; i++) {
            if (ResourceItems[i].wResourceType != NULL) {
                if (UnicodeCmp(wResourceType, ResourceItems[i].wResourceType) == 0) {
                    ResExists = true;
                    break;
                }
            }
        }
    }

    /* if such type of resource already exist, add it to exist table */
    if (ResExists) {
        /* check for the same resource exist */
        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            if (ResourceItems[i].ResourceItem[j].wResourceName != NULL) {
                if (UnicodeCmp(ResourceItems[i].ResourceItem[j].wResourceName, wResourceName) == 0) {
                    if (ResourceItems[i].ResourceItem[j].Language == Language)
                        return RE_RESOURCE_ALREADY_EXIST;
                }
            } else {
                if (ResourceItems[i].ResourceItem[j].iResourceName == iResourceName) {
                    if (ResourceItems[i].ResourceItem[j].Language == Language)
                        return RE_RESOURCE_ALREADY_EXIST;
                }
            }
        }

        IncludeItemCount = ResourceItems[i].IncludeItemCount + 1;
        ResourceItems[i].iResourceType = iResourceType;
        ResourceItems[i].wResourceType = wResourceType;
        ResourceItems[i].IncludeItemCount = IncludeItemCount;
        ResourceItems[i].ResourceItem = (pResourceItem) realloc(ResourceItems[i].ResourceItem, sizeof(ResourceItem) * IncludeItemCount);

        /* increase counter */
        if (wResourceName == NULL) {
            ResourceItems[i].IdCount++;
        } else {
            ResourceItems[i].NameCount++;
        }

        AddString(&ResourceItems[i].ResourceItem[IncludeItemCount - 1].wResourceName, wResourceName);
        ResourceItems[i].ResourceItem[IncludeItemCount - 1].iResourceName = iResourceName;
        ResourceItems[i].ResourceItem[IncludeItemCount - 1].Language = Language;
        ResourceItems[i].ResourceItem[IncludeItemCount - 1].AlignSize = AlignSize;
        ResourceItems[i].ResourceItem[IncludeItemCount - 1].DataSize = DataSize;

        /* allocate memory for data or just use pointer */
        if (NoAddData == false) {
            ResourceItems[i].ResourceItem[IncludeItemCount - 1].DataPointer = (PBYTE) calloc(DataSize, 1);
            memcpy(ResourceItems[i].ResourceItem[IncludeItemCount - 1].DataPointer,
                   DataPointer,
                   DataSize - AlignSize);
        } else {
            exit(0);
            ResourceItems[i].ResourceItem[IncludeItemCount - 1].DataPointer = DataPointer;
            NoAddData = false;
        }

        return RE_SUCCESS;
    }

    /* create new table if no such type of resources */
    ResourceItems = (struct _ResourceItems*) realloc(ResourceItems, sizeof(struct _ResourceItems) * (ResourceItemsNum + 1));

    IncludeItemCount = 1;
    ResourceItems[ResourceItemsNum].iResourceType = iResourceType;
    ResourceItems[ResourceItemsNum].IncludeItemCount = IncludeItemCount;
    ResourceItems[ResourceItemsNum].IdCount = 0;
    ResourceItems[ResourceItemsNum].NameCount = 0;
    AddString(&ResourceItems[ResourceItemsNum].wResourceType, wResourceType);
    ResourceItems[ResourceItemsNum].ResourceItem = (pResourceItem) malloc(sizeof(ResourceItem) * ResourceItems[ResourceItemsNum].IncludeItemCount);

    /* increase counter */
    if (wResourceName == NULL) {
        ResourceItems[i].IdCount++;
    }  else {
        ResourceItems[i].NameCount++;
    }

    AddString(&ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].wResourceName, wResourceName);
    ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].iResourceName = iResourceName;
    ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].Language = Language;
    ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].AlignSize = AlignSize;
    ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].DataSize = DataSize;

    /* allocate memory for data or just use pointer */
    if (NoAddData == false) {
        ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].DataPointer = (PBYTE) calloc(DataSize, 1);
        memcpy(ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].DataPointer,
               DataPointer,
               DataSize - AlignSize);
    } else {
        ResourceItems[ResourceItemsNum].ResourceItem[IncludeItemCount - 1].DataPointer = DataPointer;
        NoAddData = false;
    }

    ResourceItemsNum++;
    return RE_SUCCESS;
}

int PERE::UpdateResource(DWORD iResourceType, char *cResourceType,
                         DWORD iResourceName, char *cResourceName,
                         DWORD Lang, PBYTE DataPointer, DWORD DataSize)
{
    if (cResourceType != NULL && cResourceType[0] == 0x00)
        cResourceType = NULL;

    if (cResourceName != NULL && cResourceName[0] == 0x00)
        cResourceName = NULL;

    unicode_t *wResourceType = (cResourceType) ? AsciiToUnicode(cResourceType) : NULL;
    unicode_t *wResourceName = (cResourceName) ? AsciiToUnicode(cResourceName) : NULL;

    int status = AddResource(iResourceType,
                             wResourceType,
                             iResourceName,
                             wResourceName,
                             Lang,
                             DataPointer,
                             DataSize);

    if (wResourceType) free(wResourceType);
    if (wResourceName) free(wResourceName);

    return status;
}

void PERE::SortResource(void)
{
    DWORD i, j;
    ResourceItem RIT_1;
    struct _ResourceItems RIT_2;
    bool Sorted = true;

    if (ResourceItemsNum == 0)
        return;

    /* make symbolic names first in table */
    for (i = 0; i < ResourceItemsNum; i++) {
        if (ResourceItems[i].wResourceType != NULL)
            ResourceItems[i].iResourceType = 0x00000000;

        for (j = 0; j < ResourceItems[i].IncludeItemCount; j++) {
            if (ResourceItems[i].ResourceItem[j].wResourceName != NULL)
                ResourceItems[i].ResourceItem[j].iResourceName = 0x00000000;
        }
    }

    /* sort resources id type */
    Sorted = false;
    while (!Sorted) {
        Sorted = true;
        for (i = 0; i < ResourceItemsNum - 1; i++) {
            if (ResourceItems[i].iResourceType > ResourceItems[i + 1].iResourceType) {
                RIT_2 = ResourceItems[i + 1];
                ResourceItems[i + 1] = ResourceItems[i];
                ResourceItems[i] = RIT_2;
                Sorted = false;
            }
        }
    }

    /* sort resources id name */
    for (i = 0; i < ResourceItemsNum; i++) {
        Sorted = false;
        while (!Sorted) {
            Sorted = true;
            for (j = 0; j < ResourceItems[i].IncludeItemCount - 1; j++)
                if (ResourceItems[i].ResourceItem[j].iResourceName > ResourceItems[i].ResourceItem[j + 1].iResourceName) {
                    RIT_1 = ResourceItems[i].ResourceItem[j + 1];
                    ResourceItems[i].ResourceItem[j + 1] = ResourceItems[i].ResourceItem[j];
                    ResourceItems[i].ResourceItem[j] = RIT_1;
                    Sorted = false;
                }
        }
    }

    /* sort resources type */
    Sorted = false;
    while (!Sorted) {
        Sorted = true;
        for (i = 0; i < ResourceItemsNum - 1; i++) {
            if (ResourceItems[i].wResourceType != NULL && ResourceItems[i + 1].wResourceType != NULL)
                if (UnicodeCmp(ResourceItems[i].wResourceType, ResourceItems[i + 1].wResourceType) > 0) {
                    RIT_2 = ResourceItems[i + 1];
                    ResourceItems[i + 1] = ResourceItems[i];
                    ResourceItems[i] = RIT_2;
                    Sorted = false;
                }
        }
    }

    /* sort resources name */
    for (i = 0; i < ResourceItemsNum; i++) {
        Sorted = false;
        while (!Sorted) {
            Sorted = true;
            for (j = 0; j < ResourceItems[i].IncludeItemCount - 1; j++) {
                if (ResourceItems[i].ResourceItem[j].wResourceName != NULL &&
                    ResourceItems[i].ResourceItem[j + 1].wResourceName != NULL)

                    if (UnicodeCmp(ResourceItems[i].ResourceItem[j].wResourceName,
                        ResourceItems[i].ResourceItem[j + 1].wResourceName) > 0) {
                        RIT_1 = ResourceItems[i].ResourceItem[j + 1];
                        ResourceItems[i].ResourceItem[j + 1] = ResourceItems[i].ResourceItem[j];
                        ResourceItems[i].ResourceItem[j] = RIT_1;
                        Sorted = false;
                    }
            }
        }
    }
}

int PERE::AddResourceFromMemory(PBYTE Buffer, DWORD size, DWORD iType, char *cType,
                                DWORD iName, char *cName, DWORD Lang)
{
    if (VirtualFile == NULL)
        return RE_FAIL;

    unicode_t *wType = (cType == NULL) ? NULL : AsciiToUnicode(cType);
    unicode_t *wName = (cName == NULL) ? NULL : AsciiToUnicode(cName);

    AddResource(iType, wType, iName, wName, Lang, Buffer, size);

    if (wType != NULL) free(wType);
    if (wName != NULL) free(wName);

    return RE_SUCCESS;
}

int PERE::AddResourceFromFile(char *FilePath, DWORD iType, char *cType,
                              DWORD iName, char *cName, DWORD Lang)
{
    FILE *FHandle;
    DWORD FileSize;
    unicode_t *wType, *wName;

    if (VirtualFile == NULL)
        return RE_FAIL;

    FHandle = fopen(FilePath, "rb");
    if (FHandle == NULL)
        return RE_FAIL;

    fseek(FHandle, 0, SEEK_END);
    FileSize = ftell(FHandle);
    fseek(FHandle, 0, SEEK_SET);
    VirtualFile = (PBYTE) malloc(FileSize);
    fread(VirtualFile, 1, FileSize, FHandle);
    fclose(FHandle);

    wType = (cType == NULL) ? NULL : AsciiToUnicode(cType);
    wName = (cName == NULL) ? NULL : AsciiToUnicode(cName);

    AddResource(iType, wType, iName, wName, Lang, VirtualFile, FileSize);

    if (wType != NULL) free(wType);
    if (wName != NULL) free(wName);

    return RE_SUCCESS;
}

int PERE::FindResource(DWORD iType, char *cType, DWORD iName, char *cName, pResourceInfo ResInfo)
{
    if (cType != NULL && cType[0] == 0x00)
        cType = NULL;

    if (cName != NULL && cName[0] == 0x00)
        cName = NULL;

    unicode_t *wType = (cType == NULL) ? NULL : AsciiToUnicode(cType);
    unicode_t *wName = (cName == NULL) ? NULL : AsciiToUnicode(cName);

    for (DWORD i = 0; i < PE.ResourceTableNum; i++) {
        GetResourceType(i);

        if (wType != NULL && UnicodeCmp(wType, GetResourceType_Result.cName) != 0)
            continue;

        if (wType == NULL && iType != GetResourceType_Result.iName)
            continue;

        int resources_count = GetResourceNumber(GetResourceType_Result.iName,
                                                GetResourceType_Result.cName);
        for (int j = 0; j < resources_count ; j++) {
            GetResourceInfo(GetResourceType_Result.iName, GetResourceType_Result.cName, j);

            if (wName != NULL && UnicodeCmp(wName, GetResourceInfo_Result.cName) != 0)
                continue;

            if (wName == NULL && iName != GetResourceInfo_Result.iName)
                continue;

            *ResInfo = GetResourceInfo_Result;
            return RE_SUCCESS;
        }
    }

    ResInfo->RawSize = 0;
    ResInfo->Buffer = NULL;
    return RE_FAIL;
}

int PERE::GetResourceByIndex(DWORD TypeIndex, int NameIndex, int LanguageIndex, pResourceInfo ResInfo)
{
    if (NameIndex == -1) {
        GetResourceType(TypeIndex);

        ResInfo->iName = GetResourceType_Result.iName;
        ResInfo->cName = GetResourceType_Result.cName;
        ResInfo->Buffer = NULL;
        ResInfo->RawSize = 0;
        return RE_SUCCESS;
    }

    if (TypeIndex <= PE.ResourceTableNum) {
        GetResourceType(TypeIndex);

        if (NameIndex <= GetResourceNumber(GetResourceType_Result.iName, GetResourceType_Result.cName)) {
            GetResourceInfo(GetResourceType_Result.iName, GetResourceType_Result.cName, NameIndex);
            *ResInfo = GetResourceInfo_Result;
            return RE_SUCCESS;
        }
    }

    ResInfo->RawSize = 0;
    ResInfo->Buffer = NULL;
    return RE_FAIL;
}

int PERE::GetResourceCount(int NameIndex, int LanguageIndex)
{
    if (NameIndex == -1 && LanguageIndex == -1)
        return PE.ResourceTableNum;

    if (NameIndex < 9999) {
        GetResourceType(NameIndex);

        return GetResourceNumber(GetResourceType_Result.iName,
                                 GetResourceType_Result.cName);
    }

    return 0;
}

void PERE::InitGlobalVar(void)
{
    CharNameMemorySize = 0;
    ResourceItemsNum = 0;
    CodePage = 0;
    NoAddData = false;
    SafeMode = false;
}

int PERE::BeginUpdateResource(char *FilePath, bool DeleteTable)
{
    int Status;

    if (VirtualFile != NULL)
        return RE_FAIL;

    InitGlobalVar();

    if (OpenFile(FilePath) == RE_FAIL)
        return RE_FAIL;

    Status = BeginUpdateResourceInMemory(&VirtualFile, &FileSize, DeleteTable);

    FileLoaded = true;
    return Status;
}

int PERE::BeginUpdateResourceInMemory(PBYTE *Pointer, PDWORD size, bool DeleteTable)
{
    DWORD i, j;

    if (Pointer == NULL || (VirtualFile != NULL && VirtualFile != *Pointer))
        return RE_FAIL;

    pPointer = Pointer;
    pSize = size;

    InitGlobalVar();

    VirtualFile = *Pointer;
    FileSize = *size;
    OriginalFileSize = FileSize;
    FileLoaded = false;

    ReadPEHeader();

    /* save original resource table */
    if (!DeleteTable) for (i = 0; i < PE.ResourceTableNum; i++) {
        GetResourceType(i);

        for (j = 0; j < GetResourceNumber(GetResourceType_Result.iName, GetResourceType_Result.cName); j++) {
            GetResourceInfo(GetResourceType_Result.iName, GetResourceType_Result.cName, j);
            AddResource(GetResourceType_Result.iName, GetResourceType_Result.cName,
                        GetResourceInfo_Result.iName, GetResourceInfo_Result.cName,
                        GetResourceInfo_Result.Language,
                        GetResourceInfo_Result.Buffer,
                        GetResourceInfo_Result.RawSize);
        }
    }

    RebuildTable = false;
    return RE_SUCCESS;
}

int PERE::EndUpdateResource(void)
{
    CreateResourceTable(RebuildTable);

    if (FileLoaded == true) {
        CloseFile();
        free(VirtualFile);
    } else {
        *pPointer = VirtualFile;
        *pSize = FileSize;
    }

    VirtualFile = NULL;

    return RE_SUCCESS;
}
