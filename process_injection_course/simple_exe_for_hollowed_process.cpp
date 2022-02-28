// Simple.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
	MessageBox(nullptr, L"In hollowed process!", L"Hollowed", MB_OK);
	return 0;
}
