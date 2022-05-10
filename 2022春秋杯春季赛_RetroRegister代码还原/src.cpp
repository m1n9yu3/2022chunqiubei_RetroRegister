#pragma once

/*********************************************

���ļ���Ż�ԭ�ĺ�������


*********************************************/

#include<Windows.h>

// ������û���
unsigned char aUserName[16];
// ���ܺ����������
DWORD aEncryMsgArry[9] = { 0 };

// �����������ʽ���е�һ����֤
int CheckInput(char* szUserName, char* szPassWord)
{
    // ���ݹ۲� �������� 9 * 4 ��С�� 0-4 �洢������ܺ�����ݣ� 5-8 �洢�û������ܺ������
    DWORD OutBuffer[8] = { 0 };
    unsigned char aStringTable[0x21] = { "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" };

    // ����һ�� SM3 ���ܺ��õ�һ�����ݣ�����xor ��õ��������������
    //SM3EncryPt(szUserName, strlen(szUserName), OutBuffer);

    aEncryMsgArry[5] = OutBuffer[0] ^ OutBuffer[1];
    aEncryMsgArry[6] = OutBuffer[2] ^ OutBuffer[3];
    aEncryMsgArry[7] = OutBuffer[4] ^ OutBuffer[5];
    aEncryMsgArry[8] = OutBuffer[6] ^ OutBuffer[7];

    if (strlen(szPassWord) != 0x1d)
    {
        return 0;
    }

    aEncryMsgArry[0] = 0;

    DWORD* pEncryPtAr = aEncryMsgArry;
    int nCount = 0;

    // ѭ�� 0x1d ��
    for (int j = 0, *pEncryPtAr = 0; ; j++)
    {

        int cTmp = szPassWord[j];
        int nIndex = 0;
        // �ж��ַ����Ƿ�����ڸ������ַ�����
        while (nIndex < 0x20)
        {
            if (cTmp == aStringTable[nIndex + 0])
            {
                *pEncryPtAr = (*pEncryPtAr << 5) + nIndex;
            }
            //else if (cTmp == aStringTable[nIndex + 1])
            //{
            //    *pEncryPtAr = (*pEncryPtAr << 5) + nIndex + 1;
            //}
            //else if (cTmp == aStringTable[nIndex + 2])
            //{
            //    *pEncryPtAr = (*pEncryPtAr << 5) + nIndex + 2;
            //}
            //else if (cTmp == aStringTable[nIndex + 3])
            //{
            //     *pEncryPtAr = (*pEncryPtAr << 5) + nIndex + 3;
            //}
            // nIndex += 4;
            nIndex += 1;
        }
        // ���û�У���ֱ�ӷ���0
        if (*pEncryPtAr == 0)
        {
            return 0;
        }
        nCount += 1;
        // ��� ����������ڵ��� 5 
        if (nCount >= 5)
        {
            // �����жϵ�ǰ�Ƿ񳬳�����
            if (j > 0x1d)
            {
                break;
            }
            // �жϵ�ǰ�ַ��Ƿ�Ϊ - (�涨: ������ 5�ı���λ��Ϊ - )
            if (szPassWord[j] != '-')
            {
                return 0;
            }
            pEncryPtAr = pEncryPtAr + 1;
            // ��� ��ǰλ�� ���ڵ����� szEncryPtArry[5] ���˳�ѭ���� Ӧ����ֻ��Ҫ���� 0-4 ��λ�õ����ݡ�
            if ((DWORD*)pEncryPtAr < &(aEncryMsgArry[5]))
            {
                nCount = 0;
                *pEncryPtAr = 0;
            }
            else
            {
                break;
            }
        }

    }

    int nTmp = 0;

    // ��֤ 0-4 λ�õ������Ƿ����
    if (
        (((((((((((aEncryMsgArry[0] ^ aEncryMsgArry[4]) >> 5) ^ aEncryMsgArry[0]) >> 5) ^ aEncryMsgArry[0]) >> 5) ^ aEncryMsgArry[0]) >> 5) ^ aEncryMsgArry[0]) & 0x1f) == 0)
        &&
        ((((((((((aEncryMsgArry[1] >> 5) ^ aEncryMsgArry[1]) ^ aEncryMsgArry[4]) >> 5) ^ aEncryMsgArry[1]) >> 5) ^ aEncryMsgArry[1]) >> 5 ^ aEncryMsgArry[1]) & 0x1f) == 0)
        &&
        (((((((((((aEncryMsgArry[2] >> 5) ^ aEncryMsgArry[2]) >> 5) ^ aEncryMsgArry[2]) ^ aEncryMsgArry[4]) >> 5) ^ aEncryMsgArry[2]) >> 5) ^ aEncryMsgArry[2]) & 0x1f) == 0)
        &&
        ((((((((((aEncryMsgArry[3] >> 5) ^ aEncryMsgArry[3]) >> 10) ^ (aEncryMsgArry[3] >> 5)) ^ aEncryMsgArry[3]) ^ aEncryMsgArry[4]) >> 5) ^ aEncryMsgArry[3]) & 0x1f) == 0)
        &&
        (((((((aEncryMsgArry[3] >> 5) ^ aEncryMsgArry[3]) ^ ((aEncryMsgArry[2] >> 5) ^ aEncryMsgArry[2]) ^ ((aEncryMsgArry[1] >> 5) ^ (aEncryMsgArry[1])) ^ \
            ((aEncryMsgArry[0] >> 5) ^ aEncryMsgArry[0])) >> 10 ^ ((aEncryMsgArry[3] >> 5) ^ aEncryMsgArry[3]) ^ ((aEncryMsgArry[2] >> 5) ^ aEncryMsgArry[2]) ^ \
            ((aEncryMsgArry[1] >> 5) ^ aEncryMsgArry[1]) ^ ((aEncryMsgArry[0] >> 5) ^ aEncryMsgArry[0]) >> 5) ^ \
            aEncryMsgArry[3] ^ aEncryMsgArry[2] ^ aEncryMsgArry[1]) & 0x1f)\
            == \
            (aEncryMsgArry[4] & 0x1f))
        )
    {
        return 1;
    }
    return 0;

}

// д��ע������Ϣ
int WriteRegDat()
{
    // ���ļ�
    HANDLE hFile = CreateFileA("reg.dat", 0x40000000, 0, 0, 2, 0x80, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    DWORD NumberOfBytesWritten = 0;
    DWORD Buffer[13];

    // ���ռȶ���ʽ���û���������д洢
    //*(__int64*)&Buffer = *(__int64*)aUserName;
    //*(((__int64*)&Buffer) + 1) = *(((__int64*)&aUserName) + 1);

    memcpy_s(&Buffer[0], 16, aUserName, 16);
    memcpy_s(&Buffer[4], 16, &aEncryMsgArry[5], 16);
    memcpy_s(&Buffer[8], 16, &aEncryMsgArry[0], 16);
    Buffer[12] = aEncryMsgArry[4];

    // д�ļ�
    if (WriteFile(hFile, Buffer, 0x34, &NumberOfBytesWritten, 0) != 0)
    {
        if (NumberOfBytesWritten == 0x34)
        {
            return 1;
        }
    }
    return 0;


}

// ��ȡע������Ϣ
int ReadRegData()
{
    // ���� PE �ļ�ͷ��һ�ٲ���
    HMODULE GetModuleHandleA(NULL);
    // Debug����Ϊ .text�ڱ� ���� Sm3 ���ܺ��õ���ֵ�� ֱ�ӿ۳���
    DWORD PEHEADENCRYPT[8] = { 0x26e9458a, 0x3c13520b, 0xdef20ace, 0xa703f8c1, 0x43dc0b29, 0x7e4a7fa7, 0x725366c3, 0x80680cfc };


    DWORD NumberOfBytesWritten = 0;
    DWORD Buffer[13];
    memset(Buffer, 0, 0x34);

    HANDLE hFile = CreateFileA("reg.dat", 0x80000000, 1, 0, 3, 0x80, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    if (ReadFile(hFile, Buffer, 0x34, &NumberOfBytesWritten, 0) == 0)
    {
        CloseHandle(hFile);
        return 0;
    }

    // 0-3 ��䵽 aUserName �� 16λ
    for (int i = 0; i < 4; i++)
    {
        *((DWORD*)aUserName + i) = Buffer[i];
    }
    // 4-7 �� 12 ���� xor �� ��䵽 szEncryPtArry[5] ֮���λ�� 16 λ
    for (int i = 0; i < 4; i++)
    {
        aEncryMsgArry[i + 5] = Buffer[i + 4] ^ PEHEADENCRYPT[i];
    }

    // 8-11 ��䵽 szEncryPtArry[0] ֮��� 16λ
    for (int i = 0; i < 4; i++)
    {
        aEncryMsgArry[i] = Buffer[i + 8];
    }
    // szEncryPtArry[4] = Buffer[12]  4λ
    aEncryMsgArry[4] = Buffer[12];
    return 1;
}

// ���ע������Ϣ�Ƿ���ȷ
int CheckRegData()
{

    size_t nCount = 32;

    DWORD n0 = 0;
    DWORD n1 = ((aEncryMsgArry[5] << 7) | (aEncryMsgArry[7] & 0x0FE03FFFF)) << 0x12;
    DWORD n2 = ((aEncryMsgArry[6] << 7) | (aEncryMsgArry[8] & 0x0FE03FFFF)) << 0x12;
    DWORD n3 = aEncryMsgArry[8] & 0x1FFFFFF;
    DWORD n4 = aEncryMsgArry[7] & 0x1FFFFFF;

    //DWORD n5 = aEncryMsgArry[3];
    //DWORD n6 = aEncryMsgArry[2];

    DWORD n5 = 0x1127;
    DWORD n6 = 0x1852;


    while (nCount-- != 0)
    {
        n6 += ((n0 - 0x0C39582) + n5) ^ ((n5 << 5) + n2) ^ ((n5 << 4) + n1);
        n6 = n6 & 0x1FFFFFF;
        n5 += ((n0 - 0x0C39582) + n6) ^ ((n6 << 5) + n3) ^ ((n6 << 4) + n4);
        n5 = n5 & 0x1FFFFFF;
        n0 = n0 + 0x13C6A7E;
    }

    if (n6 == 0x1852 && n5 == 0x1127)
    {
        // Sucess
    }
    else
    {
        // Fail
    }

    return 0;
}
