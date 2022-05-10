#pragma once

/*********************************************

该文件存放还原的函数代码


*********************************************/

#include<Windows.h>

// 输入的用户名
unsigned char aUserName[16];
// 加密后的数据内容
DWORD aEncryMsgArry[9] = { 0 };

// 对输入密码格式进行的一个验证
int CheckInput(char* szUserName, char* szPassWord)
{
    // 根据观察 加密数据 9 * 4 大小， 0-4 存储密码加密后的数据， 5-8 存储用户名加密后的数据
    DWORD OutBuffer[8] = { 0 };
    unsigned char aStringTable[0x21] = { "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" };

    // 经过一个 SM3 加密后，拿到一组数据，进行xor 后得到后续运算的依据
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

    // 循环 0x1d 次
    for (int j = 0, *pEncryPtAr = 0; ; j++)
    {

        int cTmp = szPassWord[j];
        int nIndex = 0;
        // 判断字符串是否出现在给定的字符表中
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
        // 如果没有，则直接返回0
        if (*pEncryPtAr == 0)
        {
            return 0;
        }
        nCount += 1;
        // 如果 运算次数大于等于 5 
        if (nCount >= 5)
        {
            // 首先判断当前是否超出索引
            if (j > 0x1d)
            {
                break;
            }
            // 判断当前字符是否为 - (规定: 密码中 5的倍数位必为 - )
            if (szPassWord[j] != '-')
            {
                return 0;
            }
            pEncryPtAr = pEncryPtAr + 1;
            // 如果 当前位置 大于等于于 szEncryPtArry[5] 则退出循环。 应该是只需要加密 0-4 的位置的数据。
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

    // 验证 0-4 位置的数据是否合理。
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

// 写入注册码信息
int WriteRegDat()
{
    // 打开文件
    HANDLE hFile = CreateFileA("reg.dat", 0x40000000, 0, 0, 2, 0x80, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    DWORD NumberOfBytesWritten = 0;
    DWORD Buffer[13];

    // 按照既定格式对用户名密码进行存储
    //*(__int64*)&Buffer = *(__int64*)aUserName;
    //*(((__int64*)&Buffer) + 1) = *(((__int64*)&aUserName) + 1);

    memcpy_s(&Buffer[0], 16, aUserName, 16);
    memcpy_s(&Buffer[4], 16, &aEncryMsgArry[5], 16);
    memcpy_s(&Buffer[8], 16, &aEncryMsgArry[0], 16);
    Buffer[12] = aEncryMsgArry[4];

    // 写文件
    if (WriteFile(hFile, Buffer, 0x34, &NumberOfBytesWritten, 0) != 0)
    {
        if (NumberOfBytesWritten == 0x34)
        {
            return 1;
        }
    }
    return 0;


}

// 读取注册码信息
int ReadRegData()
{
    // 对着 PE 文件头部一顿操作
    HMODULE GetModuleHandleA(NULL);
    // Debug出来为 .text节表 放入 Sm3 加密后拿到的值， 直接扣出来
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

    // 0-3 填充到 aUserName 中 16位
    for (int i = 0; i < 4; i++)
    {
        *((DWORD*)aUserName + i) = Buffer[i];
    }
    // 4-7 与 12 进行 xor 后 填充到 szEncryPtArry[5] 之后的位置 16 位
    for (int i = 0; i < 4; i++)
    {
        aEncryMsgArry[i + 5] = Buffer[i + 4] ^ PEHEADENCRYPT[i];
    }

    // 8-11 填充到 szEncryPtArry[0] 之后的 16位
    for (int i = 0; i < 4; i++)
    {
        aEncryMsgArry[i] = Buffer[i + 8];
    }
    // szEncryPtArry[4] = Buffer[12]  4位
    aEncryMsgArry[4] = Buffer[12];
    return 1;
}

// 检查注册码信息是否正确
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
