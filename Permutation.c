#pragma warning(disable:4996)
#pragma warning(disable:6031)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void Enc(char[], int, int, int);
void Dec(char[], int, int, int);

int main(void) {

	char userInput[100];
	int key;
	int len;
	int size;
	int choice;

	printf("##################################################\n\n");

	while (1) {
		printf("1. Encrypt\n2. Decrypt\n\nChoose : ");
		scanf(" %d", &choice);

		printf("Input Text(AtoZ) : \n");
		scanf(" %[^\n]s", userInput);

		len = strlen(userInput);

		printf("Input seed : \n");
		scanf(" %d", &key);

		printf("Input slice size : \n");
		scanf(" %d", &size);


		if (choice == 1) {
			printf("Encrypted Text : \n");
			Enc(userInput, key, len, size);
		}
		else if (choice == 2) {
			printf("Decrypted Text : \n");
			Dec(userInput, key, len, size);
		}

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

		if (i >= 0 && i <= (len - (len % size))-1 ) {
			encrypted[i] = plain[size * k + a[i % size]];
		}
		else {
			encrypted[i] = plain[size * k + a[(i % size)]%(len%size)];
		}

		if (encrypted[i] == '?') {
			encrypted[i] = ' ';
		}
		printf("%c", encrypted[i]);

	}

	return;
}


void Dec(char plain[], int key, int len, int size) {
	int i = 0;
	int j = 0;
	int k = 0;
	int min = 0;
	int a[100];
	int b[100];
	char decrypted[100];

	b[0] = 0;

	srand(key);

	for (i = 0; i < size; i++) {
		a[i] = (rand() % size);
		for (j = 0; j < i; j++) {
			if (a[i] == a[j]) {
				i--;
			}
		}
	}


	for (i = 0; i < size; i++) {
		for (j = 0; j < size; j++) {
			if (a[j] == min) {
				b[i] = j;
				min++;
				break;
			}
		}
	}


	for (i = 0; i < len; i++) {
		if (i != 0 && i % size == 0) {
			k++;
		}

		if (i >= 0 && i <= (len - (len % size)) - 1) {
			decrypted[i] = plain[size * k + b[i % size]];
		}
		else {
			decrypted[i] = plain[size * k + b[(i % size)] % (len % size)];
		}

		if (decrypted[i] == '?') {
			decrypted[i] = ' ';
		}
		printf("%c", decrypted[i]);

	}

	return;
}
