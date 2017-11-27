#include "libvis.h"

vis_file_t* OpenVisFile(const char* fname)
{
	vis_file_t *VF = malloc(sizeof(*VF));
	if(!VF)
	{
		return 0;
	}
	header = data = crypto = zip = 0;
	fmt = type = size = 0;
	FILE* F = 0;

	F = fopen(fname,"rb");
	if( !F ) return 1;
	fseek(F,0,SEEK_END);
	int size = ftell(F);
	fseek(F,0,0);
	if( size == 0 || ( size < sizeof(int)*4) ) //long
	{
		fclose(F);
		return 2;
	}
	header = new char[size+1];
	data = header;    
	data[size] = 0;
	uint32_t rsize = 0;
	rsize = fread(data,1,size,F);
	fclose(F);
	if( size != rsize )
	{
		Close();
		return 3;
	}

	bool ch = false;
	for(;data < header+size; data++)
	{
		if(*data == 0xA || *data == 0xD)
		{
			ch = true;
			*data = ' ';
			data++;
			if(*data == 0xA || *data == 0xD) data++;
			break;
		}
	}
	dlen = size - (data-header);
	
	if(!ch) { Close(); return 4; }

	const char* hw = header;
	uint32_t reg = *(uint32_t*)(hw) & g3b;
	if(reg != SUis ) {Close(); return 5;} //"uis "
	hw += 4;
	while(hw < data-3) //2 symb + EoL
	{
		reg = *(uint32_t*)(hw) & g3b;
		char* temp;
		switch(reg)
		{
		case STxt:
			type = VIS_TXT;
			hw += 4;
			this->size = 4;
			break;
		case SBin:
			type = VIS_BIN;
			hw += 3;
			int z;
			temp = substrcpy(&hw,' ');
			sscanf(temp, "%i", &reg);
			this->size = 1 << reg;
			delete[] temp;
			break;
		case SCrp:
			if( fmt == VIS_SMP ) fmt = VIS_CRP;
			if( fmt == VIS_ZIP ) fmt = VIS_ZIPCRP;
			hw += 3;
			if(*hw == ' ') { hw++; crypto = new char[1]; *crypto = 0; }
			else crypto = substrcpy(&hw,' ');
			break;
		case SZip:
			if( fmt == VIS_SMP ) fmt = VIS_ZIP;
			if( fmt == VIS_CRP ) fmt = VIS_CRPZIP;
			hw += 3;
			if(*hw == ' ') { hw++; zip = new char[1]; *zip = 0; }
			else zip = substrcpy(&hw,' ');
			break;
		default:
			Close();
			return 6;
		}
	}

	return VF;
}

int GetLastFormat(VisFile* VF)
{
	switch(VF->fmt)
	{
	case VIS_ZIP:
	case VIS_ZIPCRP:
		return VIS_COMPRESSED;
	case VIS_CRP:
	case VIS_CRPZIP:
		return VIS_ENCRYPTED;
	case VIS_SMP:
		return VIS_READY;
	default:
		return VIS_FAILED;
	}
}

const char* GetZip(VisFile* VF)
{
	return VF->zip;
}

const char* GetCrp(VisFile* VF)
{
	return VF->crypto;
}

const char* Decrypt(VisFile* VF, int* size)
{
	VF->Decrypt();
	*size = VF->dlen;
	return VF->data;
}

const char* Decompress(VisFile* VF, int* size)
{
	VF->Unzip();
	*size = VF->dlen;
	return VF->data;
}

VisData* Decode(VisFile* VF)
{
	VisData* VD = VF->Decode();
	delete VF;
	return VD;
}

int RGroups (VisData* VD){return VD->RGroups();}
const char* RGName (VisData* VD, int g){return VD->RGName(g);}
int RGCount(VisData* VD, int g){return VD->RGCount  (g);}
int   RGESize  (VisData* VD, int g, int i) {return VD->RGESize  (g,i);}
const char* RGEName  (VisData* VD, int g, int i) {return VD->RGEName  (g,i);}

int   RObjects (VisData* VD)         {return VD->RObjects ();}
int   ROIndex  (VisData* VD, int o)       {return VD->ROIndex  (o);}
int   ROGroup  (VisData* VD, int o)       {return VD->ROGroup  (o);}
int   ROCount  (VisData* VD, int o)       {return VD->ROCount  (o);}
int   ROEType  (VisData* VD, int o, int list, int massive, int index) {return VD->ROEType  (o,list,massive,index);}
void* ROEData  (VisData* VD, int o, int list, int massive, int index) {return VD->ROEData  (o,list,massive,index);}
int   ROESize  (VisData* VD, int o, int list, int massive, int index) {return VD->ROESize  (o,list,massive,index);}

int   RSize  (VisData* VD)         {return VD->RSize  ();}
//int   RExponent(VisData* VD)         {return VD->RExponent();}

VisData* CreateVisData(int countGroups, int countObjects, int size, int dllexponent)
{
	VisData* VD = new VisData;
	VD->SGroups(countGroups); 
	VD->SObjects(countObjects); 
	VD->SExpon(dllexponent); 
	VD->SSize(size); 
	return VD;
}
void FreeData(VisData* VD)
{
	delete VD;
}

void   SGroup   (VisData* VD, int g, const char* name, int size)           {VD->SGroup  (g, name, size);}
void   SGElement  (VisData* VD, int g, int i, const char* name, int size)       {VD->SGElement (g,i,name,size);}

void   SObject  (VisData* VD, int o, int index, int g, int size)       {VD->SObject   (o,index,g,size);}
void   SOEElement (VisData* VD, int o, int list, int massive, int index, int Type, void* val, int size) {VD->SOEElement(o,list,massive,index,Type,val,size);}

void*  GetData(VisData* VD, const char* _group, const char* _property, int _object, int _list, int _index, int* size, int* type)
{
	VisElement* VE = VD->Property(_object, _group, _property, _list, _index);
	if(!VE) return 0;
	if(size) *size = VE->Length; 
	if(type) *type = VE->Type; 
	return VE->VData;
}

int CountIndexes(VisData* VD, const char* _group)
{
	int g = VD->Group(_group);
	if(g == -1) return 0;
	int c = 0;
	for(int o = 0; o < VD->countO; o++)
	{
		if(VD->obj[o].group == g) c++;
	}
	return c;
}

int GetIndex(VisData* VD, const char* _group, int i)
{
	int g = VD->Group(_group);
	if(g == -1) return -1;
	int c = -1;
	for(int o = 0; o < VD->countO; o++)
	{
		if(VD->obj[o].group == g) c++;
		if(c == i) return VD->obj[o].index;
	}
	return -1;
}
int CountLists(VisData* VD, const char* _group, int index)
{
	int g = VD->Group(_group);
	if(g == -1) return -1;
	for(int o = 0; o < VD->countO; o++)
	{
		if((VD->obj[o].group == g)&&(index == VD->obj[o].index))
			return VD->obj[o].count / VD->group[VD->obj[o].group].e_count;
	}
	return -1;
}

VisFile* EncodeBin(VisData* VD)
{
	VisFile* VF = new VisFile;
	VF->EncodeBin(VD); 
	return VF;
}
VisFile* EncodeTxt(VisData* VD)
{
	VisFile* VF = new VisFile;
	VF->EncodeTxt(VD); 
	return VF;
}
char* Encrypt(VisFile* VF, const char* Crp, int* size)
{
	VF->Crypt(Crp);
	*size = VF->dlen;
	return VF->data;
}
char* Compress(VisFile* VF, const char* Zip, int* size)
{
	VF->Zip(Zip);
	*size = VF->dlen;
	return VF->data;
}
int SaveFile(VisFile* VF, const char* fname){int val; if(!fname) {delete VF; val = 0; } else {val = VF->Save(fname); } if(!val) delete VF; return val;}

void FloatME(int mold, int mnew, int eold, int enew, void* source, void* dest){floatME(dest,source,enew,mnew,eold,mold);}
void IntegerS(int sold, int snew, char* source, char* dest){integerS(dest,source,snew,sold);}
void IntegerU(int sold, int snew, char* source, char* dest){integerU(dest,source,snew,sold);}
int Reset(VisFile* VF, const char* data, unsigned int size){return VF->Reset(data,size);}

void floatME(void* destination, void* source, int ed, int md, int es, int ms)
{
	const int flm = 23;
	const int fle = 8;
	const int dom = 52;
	const int doe = 11;

	double d = 0.0;

	if(es == fle && ms == flm)
	{
		float f = *(float*)source;
		d = (double)f;
	}
	if(es == doe && ms == dom)
	{
		d = (*(double*)source);
	}

	if(ed == fle && md == flm)
	{
		float f = (float)d;
		*(float*)destination = f;
	}
	if(ed == doe && md == dom)
	{
		*(double*)destination = d;
	}
}

/*void floatME(void* destination, void* source, int ed, int md, int es, int ms)
{  
		//ex: double -> float
		//es(11) ms(52); ed(8) md(23)
		int edif = ed - es; //8-11 = -3

		char* dest = static_cast<char*>(destination);
		char* sour = static_cast<char*>(source);  

		if(((ed+md+1)%8 != 0)||((es+ms+1)%8 != 0)) return; //octi biti

		if(ed == es && md == ms) //aequaliter
		{
				for(int i = 0; i < ((ed+ms+1)/8); i++) dest[i] = sour[i];
				return;
		}

		int esb = es; //11
		int edb = ed; //8

		char maskMD, maskED, maskMS, maskES;
		maskMD = md % 8; md /= 8; //7;2
		maskED = (ed+1) % 8; ++ed /= 8; //1;1
		maskMS = ms % 8; ms /= 8; //4;6
		maskES = (es+1) % 8; ++es /= 8; //4;1

		int mdif = (8-maskMD) - (8-maskMS); //(8-7)-(8-4)=5

		char mask;

		for(mask = 0; maskED; maskED--)
		{
				mask++;
				ROR(mask);
		}

		//0 - 1 - 10000000

		maskED = mask; //x80

		for(mask = 0; maskES; maskES--)
		{
				mask++;
				ROR(mask);
		}

		//0 - 1 - 10000000
		//10000000 - 10000001 - 11000000
		//...11100000
		//...11110000

		maskES = mask; //xf0

		maskMD = (char)(0xff)-maskED; //x7f
		maskMS = (char)(0xff)-maskES; //x0f

		char* mantiss = new char[max(md,ms)+1]; //2/6 - 7
		char* dllexponent = new char[max(ed,es)+1]; //1/1 - 2
		char sign;

		for(int i = 0; i <= es; i++) dllexponent[i] = sour[es+ms-i];
		dllexponent[es] &= maskES; //sine mantissae
		sign = dllexponent[0] & 0x80; //primus bitus exponentae

		for(int i = 0; i <= ms; i++) mantiss[i] = sour[ms-i];
		mantiss[0] &= maskMS; //sine exponentae

		//est 0?
		char mtest = 0;
		char etest = 0;
		for(int i = 1; i <= ms; i++) mtest |= mantiss[i];
		for(int i = 1; i < es; i++) etest |= dllexponent[i];

		mtest |= mantiss[0] & maskMS;
		etest |= dllexponent[0] & 0x7f;
		etest |= dllexponent[es] & maskES;
		if(mtest == 0 && etest == 0)
		{    
				for(int i = md+ed; i > 0; i--) ((char*)dest)[i] = 0;
				dest[md+ed] |= sign;
				delete[] mantiss;
				delete[] dllexponent;
				return;
		}

		//Infinitus seu NaN?
		etest = 0xff;
		for(int i = 1; i < es; i++) etest &= dllexponent[i];
		etest &= dllexponent[0] | 0x80;
		etest &= dllexponent[es] | maskMS;
		if(etest == (char)(0xff))
		{
				dest[md+ed] = 0x7f;
				for(int i = 1; i < ed; i++) dest[md+ed-i] = 0xff;
				dest[md+ed] |= sign;
				dest[md] = maskED;

				if(mtest == 0) //infinitus
				{      
						for(int i = 1; i <= md; i++) dest[md-i] = 0;
				} else { //NaN
						for(int i = 1; i <= md; i++) dest[md-i] = 0xff;
						dest[md] = 0xff;
				}
				delete[] mantiss;
				delete[] dllexponent;
				return;
		}

		dllexponent[0] &= 0x7f; //sine signo
		dllexponent[es] |= maskMS;

		ExpCor(es,dllexponent);

		char regval = dllexponent[0] & 0x80;
		if(regval) regval = 0xff;

		if( edif > 0 )
		{
				__asm
				{
						push ecx;
						push edx;
						push eax;

						mov ecx, [edif];
				repeat:

						mov edx, [ed];
						inc edx;
						MOV eax,[dllexponent];
						push uint32_t ptr [regval];
				rbytes:
						popfd;
						rcr byte ptr [EAX],1;
						pushfd;
						inc EAX;
						dec edx;
						jnz rbytes;

						add esp,4;
						dec ecx;
						jnz repeat;

						pop eax;
						pop edx;
						pop ecx;
				}
				dllexponent[0] &= 0x7f;
				//dllexponent[ed] |= maskMD;
		} else {
				if(edif != 0)
				{
						char fail = 0;
						__asm
						{
								push ecx;
								push edx;
								push eax;
								push ebx;

								mov al,[regval];
								inc al;
								jz RMin //if was 0xff
								mov EBX, Test2;
								jmp RSet;
						RMin:
								mov EBX, Test1;
						RSet:

								mov ecx, [edif];
						repeat2:      

								mov edx, [es];
								MOV eax,[dllexponent];
								ADD eax,edx;
								inc edx;
								push 0;
						rbytes2:            
								popfd;
								rcl byte ptr[EAX],1;
								pushfd;
								dec eax;
								dec edx;
								jnz rbytes2;
								jmp EBX;

						Test1:
								popfd;
								jc NoFail;
								mov [fail],0xff;
								jmp NoFail;
						Test2:
								popfd;
								jnc NoFail;
								mov [fail],0xff;
						NoFail:
								inc ecx;
								jnz repeat2;

								pop ebx;
								pop eax;
								pop edx;
								pop ecx;
						}
						if(!((!(dllexponent[0] & 0x80) && (!regval))||((dllexponent[0] & 0x80) && (regval)))) fail = 0xff;
						if(fail) //infinity
						{
								if(regval) //0
								{
										for(int i = 0; i <= md + ed; i++) dest[i] = 0;
								} else { //inf        
										dest[md+ed] = 0x7f;
										for(int i = 1; i < ed; i++) ((char*)dest)[md+ed-i] = 0xff;
										((char*)dest)[md+ed] |= sign; //sign
										((char*)dest)[md] = maskED;
										
										for(int i = 1; i <= md; i++) dest[md-i] = 0;
								}
								dest[md+ed] |= sign;

								delete[] mantiss;
								delete[] dllexponent;
								return;
						}
				}
		}

		//fake dllexponent is real + 0111....
		__asm
		{
				push eax;
				push ecx;
				mov ecx,[ed];
				mov eax,ecx;
				add eax,[dllexponent];

				push 0;

		repadd2:
				popfd;
				adc byte ptr [eax], 0xff;
				pushfd;
				dec eax;
				dec ecx;    
				jnz repadd2;
				popfd; 
				adc byte ptr [eax], 0x3f;

				pop ecx;
				pop eax;
		}

		dllexponent[0] &= 0x7f;
		dllexponent[0] |= sign;
		dllexponent[ed] &= maskED;

		//mantiss  
		if(mdif > 0)
		{
				__asm
				{
						push ecx;
						push edx;
						push eax;

						mov ecx, [mdif];
				repeatm1:      

						mov edx, [md];
						inc edx;
						MOV eax,[mantiss];
						push 0;
				rbytesm1:            
						popfd;
						rcr byte ptr [EAX],1;
						pushfd;
						inc EAX;
						dec edx;
						jnz rbytesm1;

						add esp,4;
						dec ecx;
						jnz repeatm1;

						pop eax;
						pop edx;
						pop ecx;
				}
		} else if (mdif < 0)
		{
				__asm
				{
						push ecx;
						push edx;
						push eax;

						mov ecx, [mdif];
				repeatm2:      

						mov edx, [ms];      
						MOV eax,[mantiss];
						add eax,edx;
						inc edx;
						push 0;
				rbytesm2:            
						popfd;
						rcl byte ptr [EAX],1;
						pushfd;
						dec EAX;
						dec edx;
						jnz rbytesm2;

						add esp,4;
						inc ecx;
						jnz repeatm2;

						pop eax;
						pop edx;
						pop ecx;
				}
		}
		mantiss[0] &= maskMD;

		dllexponent[ed] |= mantiss[0];

		for(int i = md; i; i--) dest[i] = mantiss[md-i];
		for(int i = ed+1; i>=0; i--) dest[md+i] = dllexponent[ed-i];


		delete[] mantiss;
		delete[] dllexponent;
		return;
}*/

void integerS(void* destination, void* source, int ld, int ls)
{
	char* dest = static_cast<char*>(destination);
	char* sour = static_cast<char*>(source);
	int dif = ld - ls;
	ld--;
	ls--;
	char sign = sour[ls] & 0x80; //sign != 0 -> source < 0
	//sour[ls] &= 0x7f;  
	if(dif < 0) //cutting
	{
		char cuttor;
		if(!sign)
		{
			cuttor = 0;
			for(int i = ld+1; i <= ls; i++) cuttor |= sour[i];
			cuttor |= sour[ld] & 0x80;
		} else {
			cuttor = 0xff;
			for(int i = ld+1; i <= ls; i++) cuttor &= sour[i];
			cuttor |= sour[ld] | 0x7f;
			if(cuttor == (char)0xff) cuttor = 0;
		}

		if(cuttor)
		{
			for(int i = 0; i <= ld; i++) dest[i] = 0xff;
			if(!sign) dest[ld] = 0x7f;
			return;
		}
								
		for(int i = 0; i <= ld; i++) dest[i] = sour[i];
		dest[ld] |= sign;

	} else 
		if (dif > 0)
		{    
			char val = sign;
			for(int i = 0; i <= ls; i++) dest[i] = sour[i];
			if(val) val = 0xff;
			for(int i = ls+1; i <= ld; i++) dest[i] = val;
		} else {
			for(int i = 0; i <= ld; i++) dest[i] = sour[i];
		}  
}

void integerU(void* destination, void* source, int ld, int ls)
{
	char* dest = static_cast<char*>(destination);
	char* sour = static_cast<char*>(source);
	int dif = ld - ls;
	ld--;
	ls--;
	if(dif < 0)
	{  
		char cutter = 0;
		for(int i = ld+1; i <= ls; i++) cutter |= sour[i];
		if(cutter)
		{
			for(int i = 0; i <= ld; i++) dest[i] = 0xff;
			return;
		}
		for(int i = 0; i <= ld; i++) dest[i] = sour[i];
	} else {
		for(int i = 0; i <= ls; i++) dest[i] = sour[i];
		for(int i = ls+1; i <= ld; i++) dest[i] = 0;
	}
}

VisFile::VisFile()
{
	header = data = crypto = zip = 0;
	fmt = type = size = 0;
	act = 0;
	dlen = 0;
}

int VisFile::GetIntS(char *& data)
{
	int val;
	integerS(&val,data,4,size);
	data += size;
	return val;
}

int VisFile::GetIntU(char *& data)
{
	int val;
	integerU(&val,data,4,size);
	data += size;
	return val;
}

void VisFile::Close()
{
	if(act) delete[] data;
	act = 0;
	dlen = 0;
	delete[] header;
	delete[] crypto;
	delete[] zip;
	header = data = crypto = zip = 0;
	fmt = VIS_ERR;
}

int VisFile::Reset(const char* _data, unsigned int _size)
{
	if(act) //header + data
	{
		char *p = data;
		data = 0;
		data = new char[_size];
		if(!data) { data = p; return 1; }
		memcpy(data,_data,_size);
		this->dlen = _size;
		delete[] p;
	} else {
		act = 0xff;
		char *pd = data;
		data = 0;
		data = new char[_size];
		if(!data) { data = pd; return 1; }
		memcpy(data,_data,_size);
		this->dlen = _size;
		delete[] header;
	}
	return 0;
}

//loading
int VisFile::Open(const char* fname)
{
}

VisData* VisFile::Decode()//if VIS_SMP
{
	if(fmt != VIS_SMP) return 0;
	VisData* VD = new VisData;
	VD->size = size; 
	int cO = 0;
	int cG = 0;

	if(type == VIS_BIN)
	{
		char* fin = data + dlen;
		int cO = 0;
		int cG = 0;
		char* z = data;

		CPVisGroup c_group = CPVisGroup();
		CPVisObj c_obj = CPVisObj();
		APVisGroup *a_group;
		APVisObj *a_obj;

		VisGroup* lgr = 0;      

		while(z < fin)
		{
			if(z + size > fin) goto ReadBinFail;
			int val = GetIntS(z);
			if(val < 0)
			{
				//descriptor
				cG++;
				a_group = c_group.Create();

				val = 0-val; //name of group
				if(z + val > fin) goto ReadBinFail;
				a_group->element->name = substrcpy(z,z+val);
				z += val;
				if(z + size > fin) goto ReadBinFail;
				val = GetIntU(z); //count of desc
				a_group->element->count = val;
				a_group->element->e_count = 0;
				a_group->element->data = new VisDesc[val];
				for(int q = 0; q < val; q++)
				{
					if(z + size > fin) goto ReadBinFail;
					int tmp = GetIntU(z); //name
					if(z + tmp > fin) goto ReadBinFail;
					a_group->element->data[q].name = substrcpy(z,z+tmp);
					z += tmp;
					if(z + size > fin) goto ReadBinFail;
					tmp = GetIntU(z); //size
					if(tmp == 0) 
					{
						if(z + size > fin) goto ReadBinFail;
						tmp = GetIntU(z); //string
						a_group->element->data[q].isstr = true;
					}
					a_group->element->data[q].size = tmp;
					a_group->element->e_count += tmp;
				}
				lgr = a_group->element;
			} else {
				//object
				cO++;
				a_obj = c_obj.Create();

				a_obj->element->index = val;
				val = GetIntU(z); //count
				if(z + val > fin) goto ReadBinFail;
				a_obj->element->count = val*lgr->e_count;
				a_obj->element->group = cG-1;
				int nel = 0;
				a_obj->element->data = new VisElement[a_obj->element->count];

				for(int q = 0; q < val; q++)
				{
					for(int gr = 0; gr < lgr->count; gr++)
					{
						int &elsize = lgr->data[gr].size;
						for(int el = 0; el < elsize; el++)
						{
							VisElement &vel = a_obj->element->data[nel];
							nel++;
							if(lgr->data[gr].isstr)
							{
								//string
								if(z + size > fin) goto ReadBinFail;
								int tmp = GetIntU(z);
								vel.Length = tmp;
								vel.Type = VT_Str;
								if(z + tmp > fin) goto ReadBinFail;
								vel.CData = substrcpy(z,z+tmp);
								z += tmp;
							} else {
								vel.Length = size;
								vel.Type = VT_IBytes;
								vel.Length = size;
								if(z + size > fin) goto ReadBinFail;
								vel.CData = subvalcpy(z,z+size);
								z += size;
							}                
						}
					}
				}
			}
		}
		goto ReadBinOK;
ReadBinFail:
		c_group.DeleteChain();
		c_obj.DeleteChain();
		delete VD;
		VD = 0;
		fmt = VIS_ERR;
		Close();
		return VD;
ReadBinOK:
		VD->countG = cG;
		VD->countO = cO;
		VD->group = new VisGroup[cG];
		VD->obj = new VisObj[cO];

		APVisGroup* group = c_group.GetFirst();
		APVisObj* obj = c_obj.GetFirst();
		for(int i = 0; i < cG; i++)
		{
			group->element->Revive(&VD->group[i]);
			group = group->next;
		}
		c_group.DeleteChain();

		for(int i = 0; i < cO; i++)
		{
			obj->element->Revive(&VD->obj[i]);
			obj = obj->next;
		}
		c_obj.DeleteChain();
	} else {      
		int ev = 0;
		char* eof;
		for(eof = data;*eof != 0;eof++) 
		{
			if( *eof == '\\' && eof[1] == '\'' ) ev--;
			if( *eof == '\'' )
			{
				ev++;
				if( ev == 2 ) ev = 0;
			}
			if( *eof == ':' && ev == 0 ) cG++;
			if( *eof == '}' && ev == 0 ) cO++; //} in correct, { in any
		}
		VD->countG = cG;
		VD->countO = cO;
		VD->group = new VisGroup[VD->countG];
		VD->obj = new VisObj[VD->countO];

		cG = 0;
		cO = 0;

		for(const char* hw = data; hw < eof;)
		{          
			for(const char* i = hw; i < eof; i++)
			{          
				if(*i == ':') //group
				{
					VisGroup& group = VD->group[cG];            

					spacefilter(&hw);
					group.name = substrcpy(hw,i);
					i++;
					hw = i;

					const char* eol = hw;
					for(ev = 0;(*eol != 0xA) && (*eol != 0xD);eol++) if(*eol == ']') ev++;
										
					group.count = ev;
					group.data = new VisDesc[ev];
					hw = eol+1;
					if(*hw == 0xA || *hw == 0xD) hw++;
					for(int q = 0;q < ev;q++)
					{
						spacefilter(&i);
						group.data[q].name = substrcpy(&i,'['); //name
						char* s = substrcpy(&i,']');
						int v;
						sscanf(s,"%i",&v);
						delete[] s;
						group.data[q].size = v;
						i++; //,
					}

					group.e_count = 0;
					for( int d = 0; d < group.count; d++ )
					{
						group.e_count += group.data[d].size;
					}

					cG++;
					hw = i;
				} 
				else if(*i == '{') //object
					{
						VisObj& obj = VD->obj[cO];

						spacefilter(&hw);
						char* z = substrcpy(hw,i);
						int v;
						sscanf(z,"%i",&v);
						delete[] z;
						obj.index = v;

						i++;
						spacefilter(&i);
						hw = i;

						const char* eol = hw;
						bool str = false;
						bool ch = false;
						for(ev = 0;;eol++)
						{
							if(!str)
							{
								if(*eol == '}')
								{
									*const_cast<char*>(eol) = ' ';
								   	break;
								}
								if(ch && *eol == ' ') ch = !ch;
								if(!ch && *eol != ' ')
								{
									ev++;
									ch = !ch;
								}
							}
							if(*eol == '\'') str = !str;
						}
						eol++;
						hw = eol;            
						obj.count = ev;
						obj.data = new VisElement[ev];
						for(int q = 0; q < ev; q++)
						{
							spacefilter(&i);
							if(*i == '\'') //string
							{
								i++;
								const char* beg = i;
								obj.data[q].CData = substrcpy(&i,'\'');
								obj.data[q].Length = i - beg -1;
								obj.data[q].Type = VT_Str;
							} else { //int/float
								char* str = substrcpy(&i,' ');
								bool fin = false;
								for(char* z = str; *z != 0; z++)
								{
									if(*z == ',') *z = '.';
									if(*z == '.') //float
									{
										float* fl = new float[1];
										sscanf(str,"%f",fl);
										obj.data[q].FData = fl;
										obj.data[q].Length = sizeof(float);
										obj.data[q].Type = VT_FBytes;
										fin = true;
										break;
									}
								}
								if( !fin )
								{
									int* iv = new int[1];
									sscanf(str,"%i",iv);
									obj.data[q].IData = iv;
									obj.data[q].Length = sizeof(int);
									obj.data[q].Type = VT_IBytes;
								}
								delete[] str;
							}
						}
					obj.group = cG-1;
					cO++;
					hw = i;
				}
			}
			break;
		}
		for(int g = 0; g < VD->countG; g++)
		{
			int o = 0;
			for(;(o < VD->countO) && (VD->obj[o].group != g); o++){}
			if((o == VD->countO) && (VD->obj[o].group != g)) continue;
			int el = 0;
			for(int i = 0; i < VD->group[g].count; i++)
			{
				if(VD->obj[o].data[el].Type == VT_Str) VD->group[g].data[i].isstr = true;
				el += VD->group[g].data[i].size;
			}
		}
	}
	Close();
	return VD;
}

void VisFile::Unzip() //marks that UnZipped
{
	switch(fmt)
	{
	case VIS_ZIPCRP:
		fmt = VIS_CRP;
		break;
	case VIS_ZIP:
		fmt = VIS_SMP;
		break;
	default:
		fmt = VIS_ERR;
	}
}

void VisFile::Decrypt()
{
	switch(fmt)
	{
	case VIS_CRPZIP:
		fmt = VIS_ZIP;
		break;
	case VIS_CRP:
		fmt = VIS_SMP;
		break;
	default:
		fmt = VIS_ERR;
	}
}

//creating
void VisFile::EncodeBin(VisData* Data)
{    
	Close();
	if(Data->Test()) return;
	this->fmt = VIS_SMP;
	this->type = VIS_BIN;

	size = Data->size;
	int len = 0;
	for(int g = 0; g < Data->countG; g++)
	{
		len += strlen(Data->group[g].name);
		for(int i = 0; i < Data->group[g].count; i++)
		{
			len += strlen(Data->group[g].data[i].name);
			len += (Data->group[g].data[i].size+1)*size; //may be 0 x
		}
		len += size*2; //namelen + child count
	}
	for(int o = 0; o < Data->countO; o++)
	{
		len += 2*size; //index + count
		for(int i = 0; i < Data->obj[o].count; i++)
		{
			len += Data->obj[o].data[i].Length;
			if(Data->obj[o].data[i].Type == VT_Str) len += size;
		}
	}
	len++; //zero

	act = 0xff; //data + header
	data = new char[len];
	char* p = data;

	int val;

	for(int g = 0; g < Data->countG; g++) 
	{
		val = 0-strlen(Data->group[g].name);
		integerS(p,&val,size,sizeof(int)); //namelen
		p += size;
		subvalcpy(Data->group[g].name, Data->group[g].name-val, p); //len
		integerS(p,&Data->group[g].count,size,sizeof(int)); //count
		p += size;

		for(int i = 0; i < Data->group[g].count; i++)
		{
			val = strlen(Data->group[g].data[i].name); //namelen
			integerS(p,&val,size,sizeof(int));
			p += size;
			subvalcpy(Data->group[g].data[i].name, Data->group[g].data[i].name+val, p); //name

			if(Data->group[g].data[i].isstr) //0size
			{
				val = 0;
				integerS(p,&val,size,sizeof(int));
				p += size;
			}
			integerS(p,&(Data->group[g].data[i].size),size,sizeof(int)); //size
			p += size;
		}

		for(int o = 0; o < Data->countO; o++)
		{
			if(Data->obj[o].group == g)
			{
				//index
				integerS(p,&Data->obj[o].index,size,sizeof(int));
				p += size;
				//count
				val = Data->obj[o].count / Data->group[g].e_count;
				integerU(p,&val,size,sizeof(int));
				p += size;

				for(int i = 0; i < Data->obj[o].count; i++)
				{
					if(Data->obj[o].data[i].Type == VT_Str)
					{
						val = Data->obj[o].data[i].Length;
						integerU(p,&val,size,sizeof(int));
						p += size;
						subvalcpy(Data->obj[o].data[i].CData,Data->obj[o].data[i].CData+val,p);
					} else {
						subvalcpy(Data->obj[o].data[i].CData,Data->obj[o].data[i].CData+size,p);
					}
				}
			}
		}
	}
	*p = 0;
	dlen = p-data;
}

void VisFile::EncodeTxt(VisData* Data)
{
	Close();
	if(Data->Test()) return;
	this->fmt = VIS_SMP;
	this->type = VIS_TXT;

	size = Data->size;
	int len = 0;
	char* tmp = new char[256];
	memset(tmp,0,256);

	for(int g = 0; g < Data->countG; g++)
	{
		len += strlen(Data->group[g].name)+2; //': '
		for(int i = 0; i < Data->group[g].count; i++)
		{        
			sprintf(tmp,"[%i]",Data->group[g].data[i].size);
			len += strlen(Data->group[g].data[i].name)+strlen(tmp)+2; //', '; last is \r\n
			memset(tmp,0,256);
		}
	}
	for(int o = 0; o < Data->countO; o++)
	{      
		sprintf(tmp,"%i",Data->obj[o].index);
		len += strlen(tmp)+4; //{}\r\n
		memset(tmp,0,256);
		for(int i = 0; i < Data->obj[o].count; i++)
		{        
			if(Data->obj[o].data[i].Type == VT_Str) len += Data->obj[o].data[i].Length+2; //'\'\''
			else 
			{
				if(Data->obj[o].data[i].Type == VT_FBytes)
				{
					double d;
					floatME(&d,Data->obj[o].data[i].CData,11,52,Data->expon,Data->size*8-1-Data->expon);
					sprintf(tmp,"%f",d);
					len += strlen(tmp);
					memset(tmp,0,256);
				} else {
					int dw;
					integerS(&dw,Data->obj[o].data[i].CData,sizeof(int),Data->size);
					sprintf(tmp,"%i",dw);
					len += strlen(tmp);
					memset(tmp,0,256);
				}
			}
			len++; //space
		}
	}
	len++; //zero

	delete[] tmp;
	act = 0xff; //data + header
	data = new char[len];
	char* p = data;
	memset(p,0,len);

	double dou;
	int ival;

	for(int g = 0; g < Data->countG; g++) 
	{  
		//desc: name[size], name[size] 0xD 0xA
		//desc
		strcpy(p,Data->group[g].name);
		while(*p != 0) p++;
		*p = ':';
		p++;
		*p = ' ';
		p++;      
				
		for(int i = 0; i < Data->group[g].count; i++)
		{
			//name
			strcpy(p,Data->group[g].data[i].name);
			while(*p != 0) p++;
			//size
			sprintf(p,"[%i]",Data->group[g].data[i].size);
			while(*p != 0) p++;
			if(i == Data->group[g].count-1)
			{
				*p = 0xD; p++;
				*p = 0xA; p++;
			} else {
				*p = ','; p++;
				*p = ' '; p++;
			}
		}

		//index{val val...}
		for(int o = 0; o < Data->countO; o++)
		{
			if(Data->obj[o].group == g)
			{
				//index
				sprintf(p,"%i{",Data->obj[o].index);
				while(*p != 0) p++;

				for(int i = 0; i < Data->obj[o].count; i++)
				{
					switch(Data->obj[o].data[i].Type)
					{
					case VT_Str:
						sprintf(p,"'%s'",Data->obj[o].data[i].CData);
						break;
					case VT_FBytes:
						floatME(&dou,Data->obj[o].data[i].CData,11,52,Data->expon,Data->size*8-1-Data->expon);
						sprintf(p,"%f",dou);
						break;
					default:
						integerS(&ival,Data->obj[o].data[i].CData,4,size);
						sprintf(p,"%i",ival);
					}
					while(*p != 0) p++;
					if(i == Data->obj[o].count-1)
					{
						*p = '}';
						p++;
						*p = 0xD;
						p++;
						*p = 0xA;
						p++;
					} else {
						*p = ' ';
						p++;
					}
				}
			}
		}
	}
	*p = 0;
	dlen = p-data-2;
}

int VisFile::Save(const char* fname)
{
	if(fmt == VIS_ERR) return -1;
	FILE* F = 0;
	F= fopen(fname,"wb");
	if( !F ) return 1;

	header = new char[256];
	char* p = header;
	memset(header,0,256);
	strcpy(header,"uis ");
	p += 4;
	if(this->type == VIS_TXT)
	{
		strcpy(p,"txt\r\n");
	} else {
		int sval = -1;
		int nsize = size;
		while(nsize)
		{
			sval++;
			nsize = nsize >> 1;
		}
		sprintf(p,"bin%i",sval);

		while(*p != 0) p++;
		if(!zip)
		{
			zip = new char[2];
			zip[0] = 0;
			zip[1] = 0;
		}
		if(!crypto)
		{
			crypto = new char[2];
			crypto[0] = 0;
			crypto[1] = 0;
		}
				
		switch(fmt)
		{
		case VIS_SMP:
			break;
		case VIS_ZIP:
			sprintf(p, " zip%s",zip);
			break;
		case VIS_CRP:
			sprintf(p, " crp%s",crypto);
			break;
		case VIS_ZIPCRP:        
			sprintf(p, " zip%s crp%s",zip,crypto);        
			break;
		case VIS_CRPZIP:        
			sprintf(p, " crp%s zip%s",zip,crypto);        
			break;
		}
		while(*p != 0) p++;
		*p = 0xD;
		p++;
		*p = 0xA;
		p++;
	}

	uint32_t outs;
	outs = strlen(header);
	if( fwrite(header,1,outs,F) != outs) {fclose(F); return 2;}
	//SetFilePointer(F,strlen(header),0,FILE_BEGIN); WTF???
	outs = dlen;
	if( fwrite(data,1,dlen,F) != dlen) {fclose(F); return 2;}
	fclose(F);

	delete[] header;
	header = 0;

	return 0;
}

void VisFile::Zip(const char* info)
{
	delete[] zip;
	int i = strlen(info);
	zip = new char[i+1];
	strcpy(zip,info);
	zip[i] = 0;

	switch(fmt)
	{
	case VIS_CRP:
		fmt = VIS_ZIPCRP;
		break;
	case VIS_SMP:
		fmt = VIS_ZIP;
		break;
	default:
		fmt = VIS_ERR;
	}
}

void VisFile::Crypt(const char* info)
{
	delete[] crypto;
	int i = strlen(info);
	crypto = new char[i+1];
	strcpy(crypto,info);
	crypto[i] = 0;

	switch(fmt)
	{
	case VIS_ZIP:
		fmt = VIS_CRPZIP;
		break;
	case VIS_SMP:
		fmt = VIS_CRP;
		break;
	default:
		fmt = VIS_ERR;
	}
}

VisFile::~VisFile()
{
	Close();
}

//element by index of object, name of group, name of element and index
VisElement* VisData::Property(int _object, const char* _group, const char* _name, int _list, int _index)
{
	for(int g = 0; g < countG; g++)
	{
		if(!strcmp(group[g].name,_group))
		{
			for(int o = 0; o < countO; o++)
			{
				if((obj[o].index == _object)&&(obj[o].group == g))
				{
					_list *= group[g].e_count;
					int _massive;
					int res = 1;
					for(_massive = 0; _massive < group[g].count; _massive++)
					{
						if(!strcmp(group[g].data[_massive].name,_name))
						{
							res = 0;
							break;
						}
					}
					if(res) return 0;
					for(int i = 0; i < _massive; i++)
					{
						_list += group[g].data[i].size;
					}
					_index += _list;

					if(_index >= obj[o].count) return 0;

					return &obj[o].data[_index];
				}
			}
		}
	}
	return 0;
}

//number of group by name*/
int VisData::Group(const char* _group)
{
	for(int g = 0; g < countG; g++)
	{
		if(!strcmp(group[g].name,_group))
		{
			return g;
		}
	}
	return -1;
}

VisData::VisData():obj(0),group(0),size(0),countO(0),countG(0),expon(8){}

VisData::~VisData()
{
	delete[] group;
	delete[] obj;
	group = 0;
	obj = 0;
	size = 0;
	expon = 8;
}

//export
int   VisData::RGroups(){return countG;}
const char* VisData::RGName(int g){return group[g].name;}
int   VisData::RGCount(int g){return group[g].count;}
int   VisData::RGESize(int g, int i){return group[g].data[i].size;}
const char* VisData::RGEName(int g, int i){return group[g].data[i].name;}
				
int   VisData::RObjects(){return countO;}
int   VisData::ROIndex(int o){return obj[o].index;}
int   VisData::ROGroup(int o){return obj[o].group;}
int   VisData::ROCount(int o){return obj[o].count / group[obj[o].group].e_count;}
int   VisData::ROEType(int o, int list, int massive, int index)
{
	int g = obj[o].group;
	int listlen = group[g].e_count;
	int i = listlen*list;
	for(int z = 0; z < massive; z++)
	{
		i += group[g].data[z].size;
	}
	i += index;
	return obj[o].data[i].Type;
}

void* VisData::ROEData(int o, int list, int massive, int index)
{
	int g = obj[o].group;
	int listlen = group[g].e_count;
	int i = listlen*list;
	for(int z = 0; z < massive; z++)
	{
		i += group[g].data[z].size;
	}
	i += index;
	return obj[o].data[i].VData;
}

int   VisData::ROESize(int o, int list, int massive, int index)
{
	int g = obj[o].group;
	int listlen = group[g].e_count;
	int i = listlen*list;
	for(int z = 0; z < massive; z++)
	{
		i += group[g].data[z].size;
	}
	i += index;
	return obj[o].data[i].Length;
}
				
int   VisData::RSize(){return size;}
int   VisData::RExponent(){return expon;}

void VisData::SGroups (int count)
{
	countG = count; 
	group = new VisGroup[count];
}

void VisData::SGroup  (int g, const char* name, int size)
{
	group[g].name = VIS::substrcpy(&name,(char)0);
	group[g].count = size; 
	group[g].data = new VisDesc[size];
}

void VisData::SGElement (int g, int i, const char* name, int size)
{
	group[g].data[i].size = size;
	group[g].e_count += size;
	group[g].data[i].name = VIS::substrcpy(&name,(char)0);
}

void VisData::SObjects(int count)
{
	countO = count; 
	obj = new VisObj[count];
}

void VisData::SObject (int o, int index, int g, int size)
{
	obj[o].index = index; 
	obj[o].group = g; 
	size *= group[g].e_count; 
	obj[o].count = size;
	obj[o].data = new VisElement[size];
}

void VisData::SOEElement (int o, int list, int massive, int index, int Type, void* _val, int size)
{
	char *val = (char*)_val;
	int g = obj[o].group;
	int listlen = group[g].e_count;
	int i = listlen*list;
	for(int z = 0; z < massive; z++)
	{
		i += group[g].data[z].size;
	}
	i += index;
	if(!size) size = this->size; 
	obj[o].data[i].Type = Type;
	if(Type == VT_Str) group[obj[o].group].data[massive].isstr = true;
	obj[o].data[i].Length = size; 
	if(Type == VT_Str) size++; 
	obj[o].data[i].CData = VIS::subvalcpy(val, val+size);
}

int VisData::Test()
{
	if((countO <= 0)||(countG <= 0)) return 1;
	else
	{
		for(int o = 0; o < countO; o++)
		{
			if((obj[o].data == 0)||(obj[o].group >= countG)) return 1;
			for(int i = 0; i < obj[o].count; i++)
			{
				if(obj[o].data[i].VData == 0) return 1;
			}
		}
		for(int g = 0; g < countG; g++)
		{
			if((group[g].data == 0)||(group[g].name == 0)) return 1;
			int x = 0;
			for(int i = 0; i < group[g].count; i++)
			{
				if(group[g].data[i].name == 0) return 1;
				x += group[g].data[i].size;
			}
			if(x != group[g].e_count) return 1;
		}
	}
	return 0;
}

void VisData::SSize   (int val){size = val;}
void VisData::SExpon  (int val){expon = val;}


inline void VIS::spacefilter(const char**str)
{
	for(;(**str == ' ')||(**str == (char)0xA)||(**str == (char)0xD);(*str)++);
}

inline char* VIS::substrcpy(const char* beg, const char* end)
{
	int c = end - beg;
	char* g = new char[c+1];
	char* s = g;
	while(beg < end) *g++ = *beg++;
	*g = 0;

	return s;
}

inline char* VIS::subvalcpy(const char* beg, const char* end)
{
	int c = end - beg;
	char* g = new char[c];

	char* s = g;
	while(beg < end) *g++ = *beg++;

	return s;
}

inline char* VIS::subvalcpy(const char* beg, const char* end, char* &out)
{
	int c = end - beg;
	out = new char[c];

	char *g = out;
	while(beg < end) *g++ = *beg++;

	return out;
}

inline char* VIS::sublen(const char* beg, int s)
{
	char* g = new char[s+1];
	char* t = g;
	for(;s;s--) *t++ = *beg++;
	*t = 0;
	return g;
}

inline char* VIS::substrcpy(const char**str, char end)
{
	const char* r = *str;
	int i;
	for(i = 0; (*r != end)&&(*r != 0); i++, r++);
	char* g = new char[i+1];
	char* s = g;
	for(;i;i--) *g++ = *(*str)++;
	*g = 0;
	(*str)++;
	return s;
}


VisMDInfo::VisMDInfo():post(0),prev(0),count(0){}

VisGroup::VisGroup():name(0),count(0),e_count(0),data(0){};
VisGroup::~VisGroup()
{
	delete[] name;
	name = 0;
	count = 0;
	e_count = 0;
	delete[] data;
	data = 0;
}

void VisGroup::Revive(VisGroup* VG)
{
	VG->count = count;
	VG->data = data;
	VG->e_count = e_count;
	VG->name = name;
	name = 0;
	data = 0;
}

VisDesc::VisDesc():name(0),size(0),isstr(false){};
VisDesc::~VisDesc()
{
	delete[] name;
	name = 0;
	size = 0;
	isstr = false;
}

void VisDesc::Revive(VisDesc* VD)
{
	VD->name = name;
	VD->size = size;
	VD->isstr = isstr;
	name = 0;
}

VisObj::VisObj():index(0),count(0),group(0),data(0){};
VisObj::~VisObj()
{
	index = 0;
	count = 0;
	group = 0;
	delete[] data;
	data = 0;
}

void VisObj::Revive(VisObj* VO)
{
	VO->index = index;
	VO->count = count;
	VO->data = data;
	VO->group = group;
	data = 0;
}

VisElement::VisElement():Length(0),Type(3),VData(0){}
VisElement::~VisElement()
{
	delete[] CData;
	VData = 0;
	Length = 0;
	Type = 3;
}

void VisElement::Revive(VisElement* VE)
{
	VE->VData = VData;
	VE->Length = Length;
	VE->Type = Type;
	VData = 0;
}
