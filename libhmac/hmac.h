/*
 * Function: hmac_md5
 *
 * text                pointer to data stream
 * text_len            length of data stream
 * key                 pointer to authentication key
 * key_len             length of authentication key
 * digest              caller digest to be filled in
 */

/*
 * $Id: hmac.h,v 1.1.1.8 2007/05/09 20:41:10 sachin Exp $
 */

#ifndef AMT_LIBHMAC_AMT_H
#define AMT_LIBHMAC_AMT_H

void hmac_md5(unsigned char* text,
      int text_len,
      unsigned char* key,
      int key_len,
      unsigned char* digest);

#endif  // AMT_LIBHMAC_AMT_H
