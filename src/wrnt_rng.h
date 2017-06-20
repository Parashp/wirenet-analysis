int __attribute__((cdecl)) GenerateRandomData(int a1, int a2) {
  int v2; // ebx@1
  int result; // eax@1
  time_t timer; // [sp+1Ch] [bp-10h]@1

  time(&timer);

  result = SeedRandom(a2 ^ timer);

  while ( v2 < a2 ) {
    result = RandomRange(1, 255);
    *(_BYTE *)(a1 + v2++) = result;
  }
  return result;
}


// n1: 0x194BD2  n2: 0x8FD18C
int __attribute__((cdecl)) SeedRandom(int a1) {

	int v1; // eax@1
	int result; // eax@1


	v1 = n1 ^ n2 & a1;
	n1 = v1;
	result = n2 ^ (a1 | v1);
	n2 = result;

	return result;
}

// Random tra 1 e 255
uint32_t __attribute__((cdecl)) RandomRange (int a1, int a2) {
	return GetRandom () % (unsigned int)(a2 - a1 + 1) + a1;
}


int32_t GetRandom () {
	n2 = (n2 << 16) + 36969 * (unsigned __int16)n2;
	n1 = (n1 << 16) + 18000 * (unsigned __int16)n1;
	return (n2 << 12) + n1;
}