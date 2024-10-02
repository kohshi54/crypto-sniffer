/* perform encryption and decryption */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // コンテキストの作成
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 暗号化初期化
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 暗号化の更新
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len = len;

    // 暗号化の最終化
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len += len;

    // コンテキストのクリーンアップ
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // コンテキストの作成
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 復号化初期化
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 復号化の更新
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;

    // 復号化の最終化
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len += len;

    // コンテキストのクリーンアップ
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(void) {
    // 暗号化と復号化に使用するキーとIV
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 256ビット（32バイト）
    unsigned char *iv = (unsigned char *)"0123456789012345"; // 128ビット（16バイト）

    unsigned char *plaintext = (unsigned char *)"This is a test message!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

	printf("Before cipher text: %s\n", plaintext);
    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);

    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted text is: %s\n", decryptedtext);

    return 0;
}

