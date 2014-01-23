#ifndef FS_H
#define FS_H

#define FS_OPEN_READ (1<<0)
#define FS_OPEN_WRITE (1<<1)
#define FS_OPEN_CREATE (1<<2)

#define FS_ATTRIBUTE_READONLY (0x00000001)
#define FS_ATTRIBUTE_ARCHIVE (0x00000100)
#define FS_ATTRIBUTE_HIDDEN (0x00010000)
#define FS_ATTRIBUTE_DIRECTORY (0x01000000)

typedef enum{
	PATH_INVALID = 0,	// Specifies an invalid path.
	PATH_EMPTY = 1,		// Specifies an empty path.
	PATH_BINARY = 2,	// Specifies a binary path, which is non-text based.
	PATH_CHAR = 3,		// Specifies a text based path with a 8-bit byte per character.
	PATH_WCHAR = 4,		// Specifies a text based path with a 16-bit short per character.
}FS_pathType;

typedef struct{
	FS_pathType type;
	u32 size;
	u8* data;
}FS_path;

typedef struct{
	u32 id;
	FS_path lowPath;
}FS_archive;


Result FSUSER_Initialize(Handle handle);
Result FSUSER_OpenFile(Handle handle, Handle* out, u32 archiveid, FS_archive archive, FS_path fileLowPath, u32 openflags, u32 attributes);

Result FSFILE_Close(Handle handle);
Result FSFILE_Read(Handle handle, u32 *bytesRead, u64 offset, u32 *buffer, u32 size);
Result FSFILE_GetSize(Handle handle, u64 *size);

#endif
