#pragma warning(disable:4996)
#pragma warning(disable:6031)

#include <stdio.h>
#include <string.h>

void Enc(char[], int, int);

int main(void) {

	char userInput[100];
	int key;
	int len;

	printf("Input Plain Text : \n");
	scanf(" %[^\n]s", userInput);

	len = strlen(userInput);

	printf("Input Key : \n");
	scanf(" %d", &key);

	printf("Encrypted Text : \n");
	Enc(userInput, key, len);


	return 0;
}


void Enc(char plain[], int key, int len) {
	int i = 0;
	while (key < 0) {
		key += 26;
	}
	key = key % 26;

	for (i = 0; i < len; i++) {
		if (plain[i] >= 'A' && plain[i] <= 'Z') {
			plain[i] -= 'A';
			plain[i] += key;
			plain[i] = plain[i] % 26;
			plain[i] += 'A';

		} else if (plain[i] >= 'a' && plain[i] <= 'z') {
			plain[i] -= 'a';
			plain[i] += key;
			plain[i] = plain[i] % 26;
			plain[i] += 'a';

		}
		
		printf("%c", plain[i]);

	}

	return;
}
