#pragma warning(disable:4996)
#pragma warning(disable:6031)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void Enc(char[], int, int, int);

int main(void) {

	char userInput[100];
	int key;
	int len;
	int size;

	printf("##################################################\n\n");

	while (1) {

		printf("Input Plain Text : \n");
		scanf(" %[^\n]s", userInput);

		len = strlen(userInput);

		printf("Input seed : \n");
		scanf(" %d", &key);

		printf("Input slice size : \n");
		scanf(" %d", &size);

		printf("Encrypted Text : \n");
		Enc(userInput, key, len, size);

		printf("\n\n##################################################\n\n");
	}


	return 0;
}


void Enc(char plain[], int key, int len, int size) {
	int i = 0;
	int j = 0;
	int k = 0;
	int a[100];
	char encrypted[100];

	srand(key);

	for (i = 0; i < size; i++) {
		a[i] = (rand() % size);
		for (j = 0; j < i; j++) {
			if (a[i] == a[j]) {
				i--;
			}
		}
	}


	for (i = 0; i < len; i++) {
		if (i != 0 && i% size == 0) {
			k++;
		}

		encrypted[i] = plain[size*k+a[i%size]];

		if (encrypted[i] == '?') {
			encrypted[i] = ' ';
		}
		printf("%c", encrypted[i]);

	}

	return;
}
