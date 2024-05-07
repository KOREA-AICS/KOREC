#pragma warning(disable:4996)
#pragma warning(disable:6031)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void Enc(char[], int, int);

int main(void) {

	char userInput[100];
	int key;
	int len;

	printf("Input Plain Text : \n");
	scanf(" %[^\n]s", userInput);

	len = strlen(userInput);

	printf("Input seed : \n");
	scanf(" %d", &key);

	printf("Encrypted Text : \n");
	Enc(userInput, key, len);


	return 0;
}


void Enc(char plain[], int key, int len) {
	int i = 0;
	int j = 0;
	int a[100];
	char encrypted[100];

	srand(key);

	for (i = 0; i < len; i++) {
		a[i] = (rand() % len);
		for (j = 0; j < i; j++) {
			if (a[i] == a[j]) {
				i--;
			}
		}
	}


	for (i = 0; i < len; i++) {
		encrypted[i] = plain[a[i]];

		printf("%c", encrypted[i]);

	}

	return;
}
