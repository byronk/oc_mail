/*
 * CRAM-MD5 authentication test tool
 * Copyright (C) 2003 Oliver Hitz <oliver@net-track.ch>
 */

#include <stdio.h>
#include "hmac_md5.h"
#include "base64.h"

int main(int argc, char *argv[]) {
  unsigned char *username;
  unsigned char *password;
  unsigned char *challenge;
  unsigned char digest[16];
  unsigned char digasc[33];
  int i;
  static char hextab[] = "0123456789abcdef";
  unsigned char *decoded;
  unsigned char *encoded;
  unsigned char *greeting;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s username password auth-greeting\n",
	    argv[0]);
    exit(1);
  }

  username = argv[1];
  password = argv[2];
  greeting = argv[3];

  challenge = b64decode_alloc(greeting);
  b64decode(greeting, challenge);

  printf("username: %s\n", username);
  printf("password: %s\n", password);
  printf("challenge: %s\n", challenge);

  hmac_md5(challenge, strlen(challenge), password, strlen(password), digest);

  digasc[32] = 0;
  for (i = 0; i < 16; i++) {
    digasc[2*i] = hextab[digest[i] >> 4];
    digasc[2*i+1] = hextab[digest[i] & 0xf];
  }

  printf("digest: %s\n", digasc);

  decoded = (unsigned char *) malloc(strlen(username)+strlen(digasc)+2);

  strcpy(decoded, username);
  decoded[strlen(username)] = ' ';
  strcpy(decoded+strlen(username)+1, digasc);
  decoded[strlen(username)+strlen(digasc)+1] = 0;

  printf("base64 decoded: %s\n", decoded);

  encoded = b64encode_alloc(decoded);
  b64encode(decoded, encoded);

  printf("base64 encoded: %s\n", encoded);

  exit(0);
}
