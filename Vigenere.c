#pragma warning(disable:4996)
#pragma warning(disable:6031)

#include <stdio.h>
#include <string.h>

void Enc(char[], char[], int, int);
void Dec(char[], char[], int, int);

int main(void) {

	char userInput[100];
	char key[100];
	int len;
	int keylen;
	int size;
	int choice;

	printf("##################################################\n\n");

	while (1) {

		printf("1. Encrypt\n2. Decrypt\n\nChoose : ");
		scanf(" %d", &choice);

		printf("Input Text(AtoZ) : \n");
		scanf(" %[^\n]s", userInput);

		len = strlen(userInput);

		printf("Input key(AtoZ) : \n");
		scanf(" %[^\n]s", key);

		keylen = strlen(key);

		if (choice == 1) {
			printf("Encrypted Text : \n");
			Enc(userInput, key, len, keylen);
		}
		else if (choice == 2) {
			printf("Decrypted Text : \n");
			Dec(userInput, key, len, keylen);
		}

		printf("\n\n##################################################\n\n");
	}


	return 0;
}


void Enc(char plain[], char key[], int len, int keylen) {
	int i = 0;
	int j = 0;
	int k = 0;
	int a[100];
	char encrypted[100];

	for (i = 0; i < len; i++) {
		if (plain[i] >= 'a' && plain[i] <= 'z') {
			plain[i] -= 'a';
			plain[i] += 'A';

		}
		if (key[i % keylen] >= 'a' && key[i % keylen] <= 'z') {
			key[i % keylen] -= 'a';
			key[i % keylen] += 'A';

		}
		
		if ( (plain[i] >= 'A' && plain[i] <= 'Z' ) && (key[i % keylen] >= 'A' && key[i % keylen] <= 'Z')) {
			encrypted[i] = ((plain[i] - 'A') + (key[i % keylen]-'A'))%26 + 'A';
			printf("%c", encrypted[i]);
		}
		else {
			printf("\nWrong Input.\n");
			break;
		}
	}


	return;
}

void Dec(char encryptedText[], char key[], int len, int keylen) {
	int i = 0;
	int j = 0;
	int k = 0;
	int a[100];
	char decrypted[100];

	for (i = 0; i < len; i++) {
		if (encryptedText[i] >= 'a' && encryptedText[i] <= 'z') {
			encryptedText[i] -= 'a';
			encryptedText[i] += 'A';

		}
		if (key[i % keylen] >= 'a' && key[i % keylen] <= 'z') {
			key[i % keylen] -= 'a';
			key[i % keylen] += 'A';

		}

		if ((encryptedText[i] >= 'A' && encryptedText[i] <= 'Z') && (key[i % keylen] >= 'A' && key[i % keylen] <= 'Z')) {
			decrypted[i] = (((encryptedText[i] - 'A') - (key[i % keylen] - 'A')) % 26 + 26) % 26 + 'A';
			printf("%c", decrypted[i]);
		}
		else {
			printf("\nWrong Input.\n");
			break;
		}
	}


	return;
}
