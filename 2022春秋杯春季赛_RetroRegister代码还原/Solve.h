#pragma once
#include<Windows.h>
#include<iostream>

#include"GmSSL-develop/include/gmssl/sm3.h"

int SM3Encrypt(uint8_t* buf, size_t  len, uint8_t* dgst);

void Solver();