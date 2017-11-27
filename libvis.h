#pragma once

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

#define VIS_READY 0
#define VIS_FAILED -1
#define VIS_COMPRESSED 1
#define VIS_ENCRYPTED 2

#define VIS_TYPE_STRING 1
#define VIS_TYPE_INTEGER 2
#define VIS_TYPE_FLOAT 3

#define VIS_SAVE_OK 0
#define VIS_SAVE_WRONG_DATA -1
#define VIS_SAVE_CREATE_FILE_ERROR 1
#define VIS_SAVE_WRITE_FILE_ERROR 2

void floatME(void* destination, void* source, int expd, int md, int exps, int ms);
void integerS(void* destination, void* source, int ld, int ls);
void integerU(void* destination, void* source, int ld, int ls);

#define VIS_BIN 0
#define VIS_TXT 1

#define VIS_SMP 0
#define VIS_CRP 1
#define VIS_ZIP 2
#define VIS_CRPZIP 3 
#define VIS_ZIPCRP 4
#define VIS_ERR 99

#define VT_Str 1
#define VT_IBytes 2
#define VT_FBytes 3
//Group: desc, ...
//Obj { elem }

#define VIS_READY 0
#define VIS_FAILED -1
#define VIS_COMPRESSED 1
#define VIS_ENCRYPTED 2

#define ROR(v){asm("ror %0,1":"=r"(v):"r"(v));}
#define ROL(v){asm("rol %0,1":"=r"(v):"r"(v));}
#define max(a,b)((a>=b)?a:b)
#define min(a,b)((a<=b)?a:b)

typedef struct vis_element_t 
{
 int Length;
 int Type;
 union
 {
  void* VData;
  int* IData;
  float* FData;
  char* CData;
 };
} vis_emenet_t;

typedef struct vis_object_t
{
 int index;
 int count;
 int group;
 vis_element_t* data;
} vis_object_t;

typedef struct vis_desc_t
{
 char* name;
 int size;
 bool isstr;
} vis_desc_t;

typedef struct vis_group_t
{
 char* name;
 int count;
 int e_count;
 vis_desc_t* data;
} vis_group_t;

typedef struct vis_md_info_t
{
 int post, prev, count;
} vis_md_info_t;

const uint32_t SUis = 0x00736975; //"uis "
const uint32_t STxt = 0x00747874; //"txt\0"
const uint32_t SBin = 0x006e6962; //"bin\0"
const uint32_t SCrp = 0x00707263; //"crp\0"
const uint32_t SZip = 0x0070697a; //"zip\0"
const uint32_t g3b = 0x00ffffff;

inline void spacefilter(const char**str); //str after space
inline char* substrcpy(const char* beg, const char* end); //new C-str
inline char* substrcpy(const char**str, char end); //new C-str + str after source
inline char* subvalcpy(const char* beg, const char* end); //new N-byte value
inline char* subvalcpy(const char* beg, const char* end, char* &out); //new N-byte value + ???
inline char* sublen(const char* beg, int s); //len from beg to first s

typedef struct vis_data_t
{ 
 int size; int expon;
 int countO,countG;
 vis_object_t* obj;
 vis_group_t* group;

 //element by index of object, name of group, name of element and index
 vis_element_t* Property(int _object, const char* _group, const char* _name, int _list, int _index);

 //number of group by name*/
 int Group(const char* _group);
 VisData();
 ~VisData();

 //export
 int   RGroups();
 const char* RGName(int g);
 int   RGCount(int g);
 int   RGESize(int g, int i);
 const char* RGEName(int g, int i);
    
 int   RObjects();
 int   ROIndex(int o);
 int   ROGroup(int o);
 int   ROCount(int o);
 int   ROEType(int o, int list, int massive, int index);
 void* ROEData(int o, int list, int massive, int index);
 int   ROESize(int o, int list, int massive, int index);
    
 int   RSize();
 int   RExponent();

 void SGroups (int count);
 void SGroup  (int g, const char* name, int size);
 void SGElement (int g, int i, const char* name, int size);

 void SObjects(int count);
 void SObject (int o, int index, int g, int size);
 void SOEElement (int o, int list, int massive, int index, int Type, void* val, int size);
 int Test();

 void SSize   (int val);
 void SExpon  (int val);
};

typedef Chain<VisGroup> CPVisGroup;
typedef ChainElement<VisGroup> APVisGroup;
typedef Chain<VisObj> CPVisObj ;
typedef ChainElement<VisObj> APVisObj ;

using namespace VIS;

struct VisFile
{
private:
 char *header;
 char act;
public:
 char *data;
 char fmt,type,size;
 char* crypto;
 char* zip;
 int dlen;

public:
 VisFile();

 int GetIntS(char *& data);
 int GetIntU(char *& data);

 void Close();

 int Reset(const char* _data, unsigned int _size);

//loading
 int Open(const char* fname);

 VisData* Decode();
 void Unzip();
 void Decrypt();
//creating
 void EncodeBin(VisData* Data);
 void EncodeTxt(VisData* Data);
 int Save(const char* fname);
 void Zip(const char* info);
 void Crypt(const char* info);

 ~VisFile();
};

EXPORT int Work();

EXPORT VisFile* OpenVisFile(const char* fname);
EXPORT int GetLastFormat(VisFile* VF);
EXPORT const char* GetZip(VisFile* VF);
EXPORT const char* GetCrp(VisFile* VF);
EXPORT const char* Decrypt(VisFile* VF, int* size);
EXPORT const char* Decompress(VisFile* VF, int* size);
EXPORT VisData* Decode(VisFile* VF);

EXPORT int RGroups (VisData* VD);
EXPORT const char* RGName (VisData* VD, int g);
EXPORT int RGCount (VisData* VD, int g);
EXPORT int RGESize (VisData* VD, int g, int i);
EXPORT const char* RGEName (VisData* VD, int g, int i);

EXPORT int RObjects (VisData* VD);
EXPORT int ROIndex (VisData* VD, int o);
EXPORT int ROGroup (VisData* VD, int o);
EXPORT int ROCount (VisData* VD, int o);
EXPORT int ROEType (VisData* VD, int o, int list, int massive, int index);
EXPORT void* ROEData (VisData* VD, int o, int list, int massive, int index);
EXPORT int ROESize (VisData* VD, int o, int list, int massive, int index);

EXPORT int RSize (VisData* VD);
//EXPORT int RExponent(VisData* VD);

EXPORT VisData* CreateVisData(int countGroups, int countObjects, int size, int dllexponent);
EXPORT void FreeData(VisData* VD);

EXPORT void SGroup (VisData* VD, int g, const char* name, int size);
EXPORT void SGElement (VisData* VD, int g, int i, const char* name, int size);

EXPORT void SObject (VisData* VD, int o, int index, int g, int size);
EXPORT void SOEElement (VisData* VD, int o, int list, int massive, int index, int Type, void* val, int size);

EXPORT void* GetData(VisData* VD, const char* _group, const char* _property, int _object, int _list, int _index, int* size, int* type);

EXPORT int CountIndexes(VisData* VD, const char* _group);
EXPORT int GetIndex(VisData* VD, const char* _group, int i);
EXPORT int CountLists(VisData* VD, const char* _group, int index);

EXPORT VisFile* EncodeBin(VisData* VD);
EXPORT VisFile* EncodeTxt(VisData* VD);
EXPORT char* Encrypt(VisFile* VF, const char* Crp, int* size);
EXPORT char* Compress(VisFile* VF, const char* Zip, int* size);
EXPORT int SaveFile(VisFile* VF, const char* fname);

EXPORT void FloatME(int mold, int mnew, int eold, int enew, void* source, void* dest);
EXPORT void IntegerS(int sold, int snew, char* source, char* dest);
EXPORT void IntegerU(int sold, int snew, char* source, char* dest);
EXPORT int Reset(VisFile* VF, const char* data, unsigned int size);
