#ifndef _LIBCAPTCHA_H_
#define _LIBCAPTCHA_H_

const int gifsize;
void captcha(unsigned char im[70*200], unsigned char l[6]);
void makegif(unsigned char im[70*200], unsigned char gif[gifsize]);

#endif
