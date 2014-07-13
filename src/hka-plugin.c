#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#include "internal.h"

#include <string.h>

#include <conversation.h>
#include <debug.h>
#include <plugin.h>
#include <request.h>
#include <signals.h>
#include <util.h>
#include <version.h>

#include "connection.h"
#include "notify.h"
#include "server.h"
#include "status.h"

#include <openssl/hmac.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "libcaptcha.h"

#define TAG_SIZE 32
#define IV_SIZE 16 // initialization vector size 
#define UC_PAK_KEY_SIZE 32


// const states
const gchar SPECIAL_TAG = 126;

const gchar INIT = 65;
const gchar INIT_RESPONSE = 66;
const gchar SEND_CAPTCHA = 67;
const gchar SEND_CAPTCHA_RESPONSE = 68;
const gchar UC_PAK_0 = 69;
const gchar UC_PAK_1 = 70;
const gchar COVERT_AKA_0 = 71;
const gchar COVERT_AKA_1 = 72;

const gchar FINISHED = 80;
 
// structures
struct HumanKeyAgreementProtocol {

        //captcha
        void (*create_captcha)(gchar** imgData, gsize* imgSize, gchar** solution);

        //binary-to-text encoding
        gchar* (*binary_to_text_encode)(const gchar* data, gsize size);
        gchar* (*text_to_binary_decode)(const gchar* data, gsize* outSize);

        //message encoding
        gchar* (*encode)(const gchar* key, const gchar* plaintext);
        gchar* (*decode)(const gchar* key, const gchar* ciphertext);
} HKA;


typedef struct __attribute__((__packed__)) {
        gchar tag;
        gchar id;
        gchar stringMsg[0]
} Message;

typedef struct __attribute__((__packed__)) {
        gsize size;
        gchar data[0];
} DataMessage;

typedef struct __attribute__((__packed__)) {
        gchar iv[IV_SIZE];
        gsize encryptedKeySize;
        gchar encryptedKey[0];  
} EncryptedKeyMessage;

typedef struct __attribute__((__packed__)) {
        gchar tag[TAG_SIZE];
        gsize publicKeySize;
        gchar publicKey[0];
} PublicKeyTagMessage;



// ------------------------------------------------- crypto --------------------------------

char* BIG_PRIME = "29061604295055353424253889135036686149137613928445910579110547029313875439718550350988053475571612683327323345153327231211393015249645532776256400727289966400641306957507901234746498758025182038940679671682664254797692666182679379869976683486935708929913042514460763209045932503591749324455446799953688622329144696410730884066597340564332192788178741520134107078162110726238941776579522198478030817552964465684161208914242979565336565429929254106908575535379162804359248056067569743805576755474787518182630886631992744331412503393707482996568555663026991098873069831574888407838245872758683738640476645977988673820659";

char* GENERATOR = "2";

void handleErrors() {
  purple_debug_misc("hka-plugin", "(Errors)\n"); 
}

void create_diffie_hellman_object(DH** dh, const char* publicKey, const char* privateKey)
{
    BIGNUM* p = NULL;
    BIGNUM* g = NULL;
    BIGNUM* priv = NULL;
    BIGNUM* pub = NULL;
    char* gen;

    if(0 == (BN_dec2bn(&p, BIG_PRIME))) handleErrors();
    if(0 == (BN_dec2bn(&g, GENERATOR))) handleErrors();
 
    if(NULL == (*dh = DH_new())) handleErrors();
    (*dh)->p = p;
    (*dh)->g = g;
    if(publicKey != NULL)
    {
        if(0 == (BN_dec2bn(&pub, publicKey))) handleErrors();   
        (*dh)->pub_key = pub;   
    }
    if(privateKey != NULL)
    {
        if(0 == (BN_dec2bn(&priv, privateKey))) handleErrors();
        (*dh)->priv_key = priv;
    }

    purple_debug_misc("hka-plugin", "create_diffie_hellman_object (created)\n"); 
    
    gen = BN_bn2dec((*dh)->g);
    purple_debug_misc("hka-plugin", "create_diffie_hellman_object (generator: %s)\n", gen);
    OPENSSL_free(gen);  
}

void generate_diffie_hellman_keys(char** publicKey, char** privateKey)
{
    DH* dh;

    create_diffie_hellman_object(&dh, NULL, NULL);

    /* Generate the public and private key pair */
    if(1 != DH_generate_key(dh)) handleErrors();
    
    *publicKey = BN_bn2dec(dh->pub_key);
    *privateKey = BN_bn2dec(dh->priv_key); 

    OPENSSL_free(dh);
}

// return secrete size
int generate_diffie_hellman_secret(const char* receivedPublicKey, const char* publicKey, const char* privateKey, char** secret)
{
    DH* dh;
    BIGNUM* receivedPublicKeyBN = NULL;
    int secretSize;
 
    create_diffie_hellman_object(&dh, publicKey, privateKey);

    BN_dec2bn(&receivedPublicKeyBN, receivedPublicKey);
  
    purple_debug_misc("hka-plugin", "create_diffie_hellman_secret (DH_size(dh): %d)\n", DH_size(dh));
    
    
    //*secret = (char*)malloc(256);

    if(NULL == (*secret = (char*)malloc(sizeof(unsigned char) * (DH_size(dh))))) handleErrors();

    //zwraca wielkosc sekretu
    if(0 > (secretSize = DH_compute_key(*secret, receivedPublicKeyBN, dh))) handleErrors();

    OPENSSL_free(dh);
    OPENSSL_free(receivedPublicKeyBN);

    return secretSize;
    
}

int hmac_sha256_vrfy(const void *key, int keySize, const unsigned char *msg, int msgSize,
               const unsigned char *tag, int tagSize) {
  
  unsigned char* newTag;
  int newTagSize;
  int i;
  
  newTag = OPENSSL_malloc(sizeof(unsigned char) * EVP_MAX_MD_SIZE);
  
  if(NULL == HMAC(EVP_sha256(), key, keySize, msg, msgSize, newTag, &newTagSize)) handleErrors();
  
  if(tagSize != newTagSize)
  {
    return 0;   
  }
  
  for(i=0; i< tagSize; i++)
  {
    if(tag[i] != newTag[i])
    {
      return 0;
    }
  }
    
  return 1;
}


void hmac_sha256(const char* key, int keySize, const char* data, int dataSize, char** tag, int* tagSize)
{
    unsigned char* digest;
    
    *tag = OPENSSL_malloc(sizeof(unsigned char) * EVP_MAX_MD_SIZE);
    
    // You may use other hash engines. e.g EVP_md5(), EVP_sha256, EVP_sha512, etc
    digest = HMAC(EVP_sha256(), key, keySize, (unsigned char*)data, dataSize, *tag, tagSize);    

    purple_debug_misc("hka-plugin", "hmac_sha256 (tag length: %d)\n", *tagSize);
      
}


void hmac_test()
{
    int i;
    int taglen;

    // The key to hash
    char key[] = "012345678";

    // The data that we're going to hash using HMAC
    char data[] = "hello world!";
    
    unsigned char* digest;
    unsigned char* tag;
    
    tag = OPENSSL_malloc(sizeof(unsigned char) * EVP_MAX_MD_SIZE);
    
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha256, EVP_sha512, etc
    digest = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), tag, &taglen);    

    purple_debug_misc("hka-plugin", "hmac_test (tag length: %d)\n", taglen);
    
    // Be careful of the length of string with the choosen hash engine. SHA1 produces a 20-byte hash value which rendered as 40 characters.
    // Change the length accordingly with your choosen hash engine
/*  char mdString[20];
    for(i = 0; i < 20; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    printf("HMAC digest: %s\n", mdString);
*/ 
/*
    printf("EVP_MAX_MD_SIZE: %d\n", EVP_MAX_MD_SIZE);
    printf("digest:\n");
    BIO_dump_fp(stdout, digest, taglen);
    printf("tag\n");
    BIO_dump_fp(stdout, tag, taglen);
*/

    if(hmac_sha256_vrfy(key, strlen(key), data, strlen(data), tag, taglen))
    {
      purple_debug_misc("hka-plugin", "hmac_test (tag verification positive)\n");   
    }
    else
    {
      purple_debug_misc("hka-plugin", "hmac_test (tag verification negative)\n");
    }
    
    OPENSSL_free(tag);
    
}

void openssl_init() 
{
  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

void openssl_clean()
{
  EVP_cleanup();
  ERR_free_strings();
}

int encrypt_aes_256(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char **ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   *    * and IV size appropriate for your cipher
   *       * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   *          * IV size for *most* modes is the same as the block size. For AES this
   *             * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  printf("block size: %d\n", EVP_CIPHER_CTX_block_size(ctx));

  *ciphertext = (unsigned char*) malloc(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));

  /* Provide the message to be encrypted, and obtain the encrypted output.
   *    * EVP_EncryptUpdate can be called multiple times if necessary
   *       */
  if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  printf("ciphertext len: %d\n", ciphertext_len);

  /* Finalise the encryption. Further ciphertext bytes may be written at
   *    * this stage.
   *       */
  if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  printf("padding len: %d\n", len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int decrypt_aes_256(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   *    * and IV size appropriate for your cipher
   *       * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   *          * IV size for *most* modes is the same as the block size. For AES this
   *             * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   *    * EVP_DecryptUpdate can be called multiple times if necessary
   *       */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   *    * this stage.
   *       */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void password_to_key(const char* password, unsigned char* key, int keySize)
{
        int i;
        //initialize key array
        for(i=0; i<keySize; i++)
        {
                if(i < strlen(password))
                {
                        key[i] = password[i];
                }
                else
                {
                        key[i] = '0';
                }
        }   
}


// ------------------------------------------------- crypto end ----------------------------

static void
hka_send_text(PurpleBuddy* buddy, gchar id, const gchar* text) 
{

        Message* msg;
        gsize msgSize;
        PurpleConnection* connection;
        PurpleAccount* account = purple_buddy_get_account(buddy);
        const gchar* name = purple_buddy_get_name(buddy);

        // get connection
        connection = purple_account_get_connection(account);
        if(!connection) {
                purple_debug_misc("hka-plugin", "hka_send_text (no connection)\n"); 
                //TODO
        }

        // prepare message
        msgSize = sizeof(Message) + strlen(text) + 1;
        msg = (Message*) g_malloc(msgSize);
        msg->tag = SPECIAL_TAG;
        msg->id = id;
        strcpy(msg->stringMsg, text);

        // send message
        serv_send_im(connection, name, (gchar*)msg, 0);

        purple_debug_misc("hka-plugin", "hka_send_text (text = %s, msg = %s)\n", text, msg);
        g_free(msg); 
}

static void
hka_send_data(PurpleBuddy* buddy, gchar id, const gchar* data, gsize dataSize)
{

        gchar* encodedDataMsg;
        DataMessage* dataMsg;
        gsize dataMsgSize;

        // prepare and encode data
        dataMsgSize = sizeof(DataMessage) + dataSize;
        dataMsg = (DataMessage*) g_malloc(dataMsgSize);
        dataMsg->size = dataSize;
        memcpy(dataMsg->data, data, dataSize);
        encodedDataMsg = HKA.binary_to_text_encode((gchar*)dataMsg, dataMsgSize);

        // send text message
        hka_send_text(buddy, id, encodedDataMsg); 
        
        g_free(dataMsg);
        g_free(encodedDataMsg);


}


static void
hka_set_protocol_state(PurpleBuddy* buddy, gchar stateId)
{
        gchar* state = g_strdup_printf("%c", stateId);
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-protocol-state", state);
        g_free(state);
}

static gchar
hka_get_protocol_state(PurpleBuddy* buddy)
{
        return *purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-protocol-state");
}

static void
hka_set_synchronized(PurpleBuddy* buddy, gboolean boolean){
        purple_blist_node_set_int((PurpleBlistNode*) buddy, "hka-synchronized", boolean);
}

static gboolean
hka_synchronized(PurpleBuddy* buddy)
{
        return purple_blist_node_get_int((PurpleBlistNode*) buddy, "hka-synchronized");
}

static void
hka_set_synchronized_msg(PurpleBuddy* buddy, const gchar* msg) 
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-synchronized-message", msg);
}

static const gchar*
hka_get_synchronized_msg(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-synchronized-message");
}

static void
hka_set_key(PurpleBuddy* buddy, const gchar* key)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-key", key);
}

static const gchar*
hka_get_key(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-key"); 
}

static void
hka_set_session_key(PurpleBuddy* buddy, const gchar* session_key)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-session-key", session_key);
}

static const gchar*
hka_get_session_key(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-session-key"); 
}

static void
hka_set_password(PurpleBuddy* buddy, const gchar* password)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-password", password);
}

static const gchar*
hka_get_password(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-password"); 
}

static void
hka_create_and_set_password(PurpleBuddy* buddy, const char* str1, const char* str2) 
{
        gchar* password = g_strdup_printf("%s%s", str1, str2);
        purple_debug_misc("hka-plugin", "hka_create_and_set_password (password = %s)\n", password);

        hka_set_password(buddy, password);
        g_free(password);
}

static void
hka_set_dh_public_key(PurpleBuddy* buddy, const gchar* key)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-dh-public-key", key);
}

static const gchar*
hka_get_dh_public_key(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-dh-public-key"); 
}

static void
hka_set_dh_private_key(PurpleBuddy* buddy, const gchar* key)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-dh-private-key", key);
}

static const gchar*
hka_get_dh_private_key(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-dh-private-key"); 
}

static void
hka_set_dh_received_key(PurpleBuddy* buddy, const gchar* key)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-dh-received-key", key);
}

static const gchar*
hka_get_dh_received_key(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-dh-received-key"); 
}


static void
hka_init_message(PurpleBuddy* buddy) 
{
        hka_send_text(buddy, INIT, " Nie masz mojego super pluginu :(");
        hka_set_protocol_state(buddy, INIT_RESPONSE);

        purple_debug_misc("hka-plugin", "hka_init_message (hka-protocol-state = %c)\n", 
                          hka_get_protocol_state(buddy)); 
}

static void
hka_init_message_response(PurpleBuddy* buddy) 
{
        hka_send_text(buddy, INIT_RESPONSE, " ");
        hka_set_protocol_state(buddy, SEND_CAPTCHA);

        purple_debug_misc("hka-plugin", "hka_init_message_response (hka-protocol-state = %c)\n", 
                          hka_get_protocol_state(buddy)); 
}

static void
hka_send_captcha(PurpleBuddy* buddy)
{
        purple_debug_misc("hka-plugin", "hka_send_captcha (beginning)\n");

        gchar* imgData;
        gsize imgSize;
        gchar* solution;

        HKA.create_captcha(&imgData, &imgSize, &solution);
        hka_set_password(buddy, solution); 

        hka_send_data(buddy, SEND_CAPTCHA, imgData, imgSize);
        hka_set_protocol_state(buddy, SEND_CAPTCHA_RESPONSE);

        g_free(imgData);
        g_free(solution);

        purple_debug_misc("hka-plugin", "hka_send_captcha (hka-protocol-state = %c)\n", 
                          hka_get_protocol_state(buddy));
}

static void
hka_send_captcha_response(PurpleBuddy* buddy)
{
        purple_debug_misc("hka-plugin", "hka_send_captcha_response (beginning)\n");

        gchar* imgData;
        gsize imgSize;
        gchar* solution;

        HKA.create_captcha(&imgData, &imgSize, &solution);
        hka_set_password(buddy, solution);

        hka_send_data(buddy, SEND_CAPTCHA_RESPONSE, imgData, imgSize);
        hka_set_protocol_state(buddy, UC_PAK_0);  // Test mode !!!

        g_free(imgData);
        g_free(solution);

        purple_debug_misc("hka-plugin", "hka_send_captcha (hka-protocol-state = %c)\n", 
                          hka_get_protocol_state(buddy));
}

static void
hka_show_info(const gchar* primaryInfo, const gchar* secondaryInfo) {
        PurplePlugin* plugin;

        plugin = purple_plugins_find_with_id("core-apachuta-hka");
  
        purple_debug_misc("hka-plugin", "hka_show_info (primaryInfo = %s)\n", primaryInfo);

        purple_request_action ( 
        plugin, // handle
        "Human Key Agreement", // title
        primaryInfo, // primary
        secondaryInfo, // secondary
        0, // default action index
        NULL, // PurpleAccount
        "Qwerty", // the username of the buddy associated with the reqest (char*)
        NULL, // PurpleConversation
        NULL, // data to pass to the callback
        1, // number of actions
        _("_OK"), // action
        NULL  // callback
  ); 

}

static void
hka_show_protocol_success_info(PurpleBuddy* buddy) 
{
        const gchar* buddyName = purple_buddy_get_alias(buddy);
        gchar* primaryInfo = g_strdup_printf("The connection with %s is now secure.", buddyName);

        hka_show_info(primaryInfo, NULL);

        g_free(primaryInfo);
}

static void
hka_show_protocol_failure_info(PurpleBuddy* buddy) 
{
        const gchar* buddyName = purple_buddy_get_alias(buddy);
        gchar* primaryInfo = g_strdup_printf("The connection with %s is NOT secure.", buddyName);

        hka_show_info(primaryInfo, NULL);

        g_free(primaryInfo);
}

// Universally-Composable Password Authenticated Key Exchange UC-PAK

static void
hka_UC_PAK_step0(PurpleBuddy* buddy) 
{
  /*
        const gchar* password = hka_get_password(buddy);

        //testmode!!
        hka_send_text(buddy, UC_PAK_0, password);
        hka_set_protocol_state(buddy, UC_PAK_1);

  */

        char* publicKey;
        char* privateKey;

        // generate DH keys
        generate_diffie_hellman_keys(&publicKey, &privateKey);
        
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step0 (pub key: %s )\n", publicKey);   
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step0 (priv key: %s )\n", privateKey);   

        // set DH keys
        hka_set_dh_public_key(buddy, publicKey);
        hka_set_dh_private_key(buddy, privateKey);

        // send DH public key
        hka_send_text(buddy, UC_PAK_0, publicKey);
        hka_set_protocol_state(buddy, UC_PAK_1);
        
        g_free(privateKey);
        g_free(publicKey);
}

static void
hka_UC_PAK_step1(PurpleBuddy* buddy, const gchar* receivedPublicKey)
{
    
    /*
        const gchar* password = hka_get_password(buddy);

        //testmode!!
        hka_set_key(buddy, msg);
        hka_set_session_key(buddy, msg);

        hka_send_text(buddy, UC_PAK_1, password);

        if(strlen(password) == 10 && strlen(msg) == 10) {
                hka_set_protocol_state(buddy, FINISHED);
                hka_show_protocol_success_info(buddy);
        }
        else{

                hka_set_protocol_state(buddy, INIT);
                hka_show_protocol_failure_info(buddy);
        }
        
    */    
        char* publicKey;
        char* privateKey;
        const char* password;
        /* A 128 bit IV */
        unsigned char *iv = "0123456789012345";
        unsigned char key[UC_PAK_KEY_SIZE];
        unsigned char* ciphertext; 
        int ciphertextSize;

        EncryptedKeyMessage* msg;
        int msgSize;

        // generate DH keys
        generate_diffie_hellman_keys(&publicKey, &privateKey);
        
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (pub key: %s )\n", publicKey);   
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (priv key: %s )\n", privateKey);   

        // set DH keys
        hka_set_dh_public_key(buddy, publicKey);
        hka_set_dh_private_key(buddy, privateKey);
        hka_set_dh_received_key(buddy, receivedPublicKey);

        // TODO generate a random IV

        /* Initialise the library */
        openssl_init();

        // encrypt public key with password
        password = hka_get_password(buddy);
        password_to_key(password, key, UC_PAK_KEY_SIZE);
        ciphertextSize = encrypt_aes_256(publicKey, strlen(publicKey), key, iv, &ciphertext);

        // TODO send encoded key and IV
        

        // prepare data to send
        msgSize = sizeof(EncryptedKeyMessage) + ciphertextSize;
        msg = (EncryptedKeyMessage*) g_malloc(msgSize);
        msg->encryptedKeySize = ciphertextSize;
        memcpy(msg->encryptedKey, ciphertext, ciphertextSize);
        memcpy(msg->iv, iv, IV_SIZE);

        // send message
        hka_send_data(buddy, UC_PAK_1, (gchar*)msg, msgSize); 

    
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (received public key: %s )\n", receivedPublicKey);

        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (sended public key: %s )\n", publicKey);
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (encryptedKeySize: %d, ivSize: %d, msgSize %d )\n", msg->encryptedKeySize, IV_SIZE, msgSize);

        hka_set_protocol_state(buddy, COVERT_AKA_0); 
        
        //openssl_clean();  // ??
        g_free(ciphertext);
        g_free(publicKey);
        g_free(privateKey);
        g_free(msg);         
}

static void
hka_UC_PAK_step2(PurpleBuddy* buddy, const gchar* stringMsg) {
    
    /*
        //testmode!!
        const gchar* password = hka_get_password(buddy);
        
        hka_set_key(buddy, msg);
        hka_set_session_key(buddy, msg);

        if(strlen(password) == 10 && strlen(msg) == 10) {
                hka_set_protocol_state(buddy, FINISHED);
                hka_show_protocol_success_info(buddy);
        }
        else{

                hka_set_protocol_state(buddy, INIT);
                hka_show_protocol_failure_info(buddy);
        }
        
    */
        DataMessage* dataMsg; 
        EncryptedKeyMessage* receivedMsg;
        gsize decodedDataSize;
        unsigned char* receivedKey;
        int receivedKeySize;
        unsigned char key[UC_PAK_KEY_SIZE];
        const char* password;
        char* secret;
        int secretSize;
        const char* publicKey;
        const char* privateKey;

        char* publicKey2;
        char* privateKey2;
        char* tag;
        int tagSize;
        PublicKeyTagMessage* msg;
        int msgSize;

        dataMsg = (DataMessage*) HKA.text_to_binary_decode(stringMsg, &decodedDataSize);
        receivedMsg = (EncryptedKeyMessage*) dataMsg->data;

        receivedKey = (unsigned char*)malloc(receivedMsg->encryptedKeySize); // plaintext is no longer than ciphertext


        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (encryptedKeySize: %d, msgSize: %d )\n", receivedMsg->encryptedKeySize, dataMsg->size);

        // decrypt a public key with a password
        password = hka_get_password(buddy);
        password_to_key(password, key, UC_PAK_KEY_SIZE); 
        receivedKeySize = decrypt_aes_256(receivedMsg->encryptedKey, receivedMsg->encryptedKeySize, key, receivedMsg->iv, receivedKey); 

        // Add a NULL terminator. We are expecting printable text  
        receivedKey[receivedKeySize] = '\0';
        
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (received and encrypted public key: %s )\n", receivedKey);

        // create DH secret
        privateKey = hka_get_dh_private_key(buddy);
        publicKey = hka_get_dh_public_key(buddy);       
        secretSize = generate_diffie_hellman_secret(receivedKey, publicKey, privateKey, &secret);

        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (public key: %s )\n", publicKey);
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (private key: %s )\n", privateKey); 
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (secret size: %d )\n", secretSize);

        // Covered AKA step 0 ---------------------------------------------------------------

        // generate new DH keys
        generate_diffie_hellman_keys(&publicKey2, &privateKey2);
        
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (new pub key: %s )\n", publicKey2);   
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (new priv key: %s )\n", privateKey2);   

        // set DH keys
        hka_set_dh_public_key(buddy, publicKey2);
        hka_set_dh_private_key(buddy, privateKey2);

        // create public key tag (with a DH secret as a key)
        hmac_sha256(secret, secretSize, publicKey2, strlen(publicKey2), &tag, &tagSize);

        if(hmac_sha256_vrfy(secret, secretSize, publicKey2, strlen(publicKey2), tag, tagSize))
        {
              purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (tag verification positive)\n");   
        }
        else
        {
             purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (tag verification negative)\n");
        }

        // prepare data to send
        msgSize = sizeof(PublicKeyTagMessage) + strlen(publicKey2) + 1;  // null terminator
        msg = (PublicKeyTagMessage*) g_malloc(msgSize);
        msg->publicKeySize = strlen(publicKey2);
        memcpy(msg->tag, tag, TAG_SIZE);
        memcpy(msg->publicKey, publicKey2, strlen(publicKey2) + 1); 

        // send message
        hka_send_data(buddy, COVERT_AKA_0, (gchar*)msg, msgSize); 


        hka_set_protocol_state(buddy, INIT); 

        g_free(dataMsg);
        g_free(receivedKey);

        g_free(privateKey2);
        g_free(publicKey2);
        g_free(secret);
}

void hka_covert_AKA_step1(PurpleBuddy* buddy, const gchar* stringMsg)
{
        DataMessage* dataMsg;
        gsize decodedDataSize;
        PublicKeyTagMessage* receivedMsg;
        const char* publicKey;
        const char* privateKey;
        const char* receivedKey;
        char* secret;
        int secretSize;
        char* publicKey2;
        char* privateKey2;
        char* tag;
        int tagSize;
               
        dataMsg = (DataMessage*) HKA.text_to_binary_decode(stringMsg, &decodedDataSize);
        receivedMsg = (PublicKeyTagMessage*) dataMsg->data;

        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (received public key: %s )\n", receivedMsg->publicKey);

        // create DH secret
        privateKey = hka_get_dh_private_key(buddy);
        publicKey = hka_get_dh_public_key(buddy);
        receivedKey = hka_get_dh_received_key(buddy);       
        secretSize = generate_diffie_hellman_secret(receivedKey, publicKey, privateKey, &secret);

        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (secretSize: %d )\n", secretSize);

        // generate new DH keys
        generate_diffie_hellman_keys(&publicKey2, &privateKey2);
        
        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (new pub key: %s )\n", publicKey2);   
        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (new priv key: %s )\n", privateKey2);   

        // create public key tag (with a DH secret as a key)
        hmac_sha256(secret, secretSize, publicKey2, strlen(publicKey2), &tag, &tagSize);
        
        // TODO send tag and PK2

        if(hmac_sha256_vrfy(secret, secretSize, receivedMsg->publicKey, receivedMsg->publicKeySize, receivedMsg->tag, TAG_SIZE))
        {
              purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (tag verification positive (with received PK and my secret))\n");   
        }
        else
        {
             purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (tag verification negative (with received PK and my secret))\n");
        }



        hka_set_protocol_state(buddy, INIT); 
        
        
        g_free(dataMsg);
        g_free(privateKey2);
        g_free(publicKey2);
        g_free(secret);
}

void hka_covert_AKA_step2(PurpleBuddy* buddy, const gchar* stringMsg)
{
        hka_set_protocol_state(buddy, INIT); 
}

static void
hka_captcha_cb(PurpleBuddy* buddy, const gchar* solution) 
{
        gchar state;
        gchar* oldPassword; 

        state = hka_get_protocol_state(buddy); 
        oldPassword = g_strdup_printf("%s", hka_get_password(buddy));

        purple_debug_misc("hka-plugin", "hka_captcha_cb (solution = %s)\n", solution);

        if(state == SEND_CAPTCHA_RESPONSE) { //test mode !!
                hka_create_and_set_password(buddy, oldPassword, solution);
                
                hka_UC_PAK_step0(buddy);

        }  
        else if(state == UC_PAK_0) { //test mode !!

                hka_create_and_set_password(buddy, solution, oldPassword);

                if(hka_synchronized(buddy)) {
                        purple_debug_misc("hka-plugin", "hka_captcha_cb (is synchronized)\n");
                        hka_set_synchronized(buddy, FALSE);
                        
                        hka_UC_PAK_step1(buddy, hka_get_synchronized_msg(buddy));

                }
                else {
                        purple_debug_misc("hka-plugin", "hka_captcha_cb (is not synchronized)\n");
                        hka_set_synchronized(buddy, TRUE);
                }
        }

        g_free(oldPassword);

}


static void
hka_cancel_captcha_cb(PurpleBuddy* buddy, PurpleRequestFields* fields) 
{
        hka_captcha_cb(buddy, "");
}

static void
hka_solved_captcha_cb(PurpleBuddy* buddy, PurpleRequestFields* fields) 
{
        const gchar* solution = purple_request_fields_get_string(fields, "solution");
        hka_captcha_cb(buddy, solution);
}

static void
hka_show_captcha(gchar* stringMsg, PurpleBuddy* buddy)
{
        gsize decodedDataSize;       
        DataMessage* dataMsg;
        PurplePlugin* plugin;
        PurpleRequestFields *request; 
        PurpleRequestFieldGroup *group; 
        PurpleRequestField *field;
        const gchar* buddyName;
        gchar* text;
        gchar state;

        state = hka_get_protocol_state(buddy); 

        buddyName = purple_buddy_get_alias(buddy); 

        if(state == SEND_CAPTCHA_RESPONSE) { 
                text = g_strdup_printf("Establish a secure connection with %s. Solve captcha:", buddyName);

        }  
        else if(state == UC_PAK_0) { 
                text = g_strdup_printf("%s wants to establish a secure connection. Solve captcha:", buddyName);
        }



        plugin = purple_plugins_find_with_id("core-apachuta-hka");

        dataMsg = (DataMessage*) HKA.text_to_binary_decode(stringMsg, &decodedDataSize);

        purple_debug_misc("hka-plugin", "hka_show_captcha (dataMsg->size = %d)\n", dataMsg->size);

        group = purple_request_field_group_new(NULL);  
       
        field = purple_request_field_image_new("captcha", "", dataMsg->data, dataMsg->size);                // add captcha image 
        purple_request_field_group_add_field(group, field);
          
        field = purple_request_field_string_new("solution", _("Solution"), "", FALSE); 
        purple_request_field_group_add_field(group, field); 
 
        request = purple_request_fields_new(); 
        purple_request_fields_add_group(request, group); 
  
        purple_request_fields(plugin, 
                         N_("Human Key Agreement"), 
                         _(text), 
                         NULL, 
                         request, 
                         _("_Set"), G_CALLBACK(hka_solved_captcha_cb), 
                         _("_Cancel"), G_CALLBACK(hka_cancel_captcha_cb), 
                         NULL, NULL, NULL, 
                         buddy);    // callback argument

        g_free(dataMsg);
}

static void
load_image(gchar** imgData, gsize* imgSize) {
        char* filename;
        filename = "/home/agnieszka/captcha.gif";
        g_file_get_contents(filename, imgData, imgSize, NULL);
}

void create_captcha(gchar** imgData, gsize* imgSize, gchar** solution) {

  unsigned char im[70*200];
  
  *imgData = (unsigned char*) g_malloc(gifsize);
  *solution = (gchar*) g_malloc(6);

  captcha(im, *solution);
  makegif(im, *imgData);

  *imgSize = gifsize;
}

static gchar*
simple_encode(const gchar* key, const gchar* plaintext){
        return g_strdup_printf("%s%s", plaintext, key);
}

static gchar*
simple_decode(const gchar* key, const gchar* ciphertext){
        return g_strndup(ciphertext, strlen(ciphertext) - strlen(key));
}

static gboolean
writing_im_msg_cb(PurpleAccount *account, char *sender, char **buffer,
					 PurpleConversation *conv, int *flags, void *data)
{ 

        return FALSE;
}


static void
sending_im_msg_cb(PurpleAccount *account, char *recipient, char **buffer, void *data)
{
        Message* msg;
        PurpleBuddy* buddy;
        gchar* encodedMsg;
        const gchar* sessionKey;
        gsize msgSize; 

        purple_debug_misc("hka-plugin", "sending_im_msg_cb (buffer: %s)\n", *buffer);
        
        buddy = purple_find_buddy(account, recipient);

        if(hka_get_protocol_state(buddy) == FINISHED) {
                        
            // encode
            sessionKey = hka_get_session_key(buddy);
            encodedMsg = HKA.encode(sessionKey, *buffer);

            // prepare message
            msgSize = sizeof(Message) + strlen(encodedMsg) + 1;
            msg = (Message*) g_malloc(msgSize);
            msg->tag = SPECIAL_TAG;
            msg->id = FINISHED;
            strcpy(msg->stringMsg, encodedMsg);

            // replace message
            g_free(*buffer);
            g_free(encodedMsg);
            *buffer = (gchar*) msg; 
        }

        purple_debug_misc("hka-plugin", "sending_im_msg_cb (buffer: %s)\n", *buffer);
}

static void
conversation_created_cb(PurpleConversation *conv, gpointer handle) //void *data)
{ 
      
}


static gboolean
receiving_im_msg_cb(PurpleAccount *account, char **sender, char **buffer,
                                     PurpleConversation *conv, PurpleMessageFlags *flags, void *data)
{
        PurpleBuddy* buddy;
        gchar state;
        Message* msg; 
        gchar* decodedMsg;
        
        msg = (Message*) *buffer;
        buddy = purple_find_buddy(account, *sender);
        state = hka_get_protocol_state(buddy); 

        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (beggining, hka-protocol-state = %c, msg->id = %c, strlen(*buffer) = %d, password = %s)\n", state, msg->id, strlen(*buffer), hka_get_password(buddy)); 

        if(msg->tag == SPECIAL_TAG && msg->id == state) {
                if(state == INIT) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (INIT)\n");
                        hka_init_message_response(buddy); 
                }
                else if(state == INIT_RESPONSE) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (INIT_RESPONSE)\n");
                        hka_send_captcha(buddy); 
                }
                else if(state == SEND_CAPTCHA) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (SEND_CAPTCHA)\n");
                        hka_send_captcha_response(buddy);
                        hka_show_captcha(msg->stringMsg, buddy);         
                }          
                else if(state == SEND_CAPTCHA_RESPONSE) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (SEND_CAPTCHA_RESPONSE)\n");
                        hka_show_captcha(msg->stringMsg, buddy); 
                }
                else if(state == UC_PAK_0 ) { 
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (UC_PAK_0)\n");

                        if(hka_synchronized(buddy)) {
                                purple_debug_misc("hka-plugin", "receiving_im_msg_cb (is synchronized)\n");
                                hka_set_synchronized(buddy, FALSE);
                                
                                hka_UC_PAK_step1(buddy, msg->stringMsg); 

                        }
                        else {
                                purple_debug_misc("hka-plugin", "receiving_im_msg_cb (is not synchronized)\n");
                                hka_set_synchronized_msg(buddy, msg->stringMsg);
                                hka_set_synchronized(buddy, TRUE);
                        }

                                        }
                else if(state == UC_PAK_1 ) { 
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (UC_PAK_1)\n");
                        hka_UC_PAK_step2(buddy, msg->stringMsg); 
                }
                else if(state == COVERT_AKA_0 ) { 
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (COVERT_AKA_0)\n");
                        hka_covert_AKA_step1(buddy, msg->stringMsg); 
                }
                else if(state == COVERT_AKA_1 ) { 
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (COVERT_AKA_1)\n");
                        hka_covert_AKA_step2(buddy, msg->stringMsg); 
                }
                else if(state == FINISHED){
                        //decode and replace message
                        decodedMsg = HKA.decode(hka_get_session_key(buddy), msg->stringMsg);
                        g_free(*buffer);
                        *buffer = decodedMsg;
                        return FALSE; //display message
                }
                else {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (else)\n");
                }

                return TRUE;
        }

         
        return FALSE;
}


// extended menu
static void
hka_start_protocol_cb(PurpleBlistNode* node, gpointer data)
{
        gchar state; 

        if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
                return;

        state = hka_get_protocol_state((PurpleBuddy*) node);

        purple_debug_misc("hka-plugin", "hka_start_protocol_cb (hka-protocol-state = %c)\n", 
                          state);

        if(state == INIT)
                hka_init_message((PurpleBuddy*) node);
        else if(state == FINISHED) 
                purple_debug_misc("hka-plugin", "hka_start_protocol_cb (state FINISHED, key = %s)\n", hka_get_key((PurpleBuddy*) node));
}
 

static void
blist_node_extended_menu_cb(PurpleBlistNode* node, GList** m)
{
        PurpleMenuAction* bna = NULL;
        
        // add extended menu only for PurpleBuddy      
        if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
                return;
 
        if (purple_blist_node_get_flags(node) & PURPLE_BLIST_NODE_FLAG_NO_SAVE)
                return;

        *m = g_list_append(*m, bna);
        bna = purple_menu_action_new(_("START PROTOCOL"), PURPLE_CALLBACK(hka_start_protocol_cb), NULL, NULL);
        *m = g_list_append(*m, bna);
        
}

static void
hka_initialize_buddy_variables(PurpleBlistNode* node) 
{
        gchar state;

        if(node == NULL)
                return;

        if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {

                if(hka_get_key((PurpleBuddy*) node) == "") {      
                        hka_set_protocol_state((PurpleBuddy*) node, INIT);
                }
                else {
                        hka_set_protocol_state((PurpleBuddy*) node, INIT ); //FINISHED);  <-- TODO
                }
                 
                hka_set_synchronized((PurpleBuddy*) node, FALSE); 
        }

        hka_initialize_buddy_variables(purple_blist_node_next(node, TRUE));
       // hka_initialize_buddy_variables(purple_blist_node_get_first_child(node));
}


// LOAD
static gboolean
plugin_load(PurplePlugin *plugin)
{
        char* pub;
        char* pub2;
        char* priv;
        char* priv2;

	void *conversation = purple_conversations_get_handle();

	purple_signal_connect(conversation, "writing-im-msg",
						plugin, PURPLE_CALLBACK(writing_im_msg_cb), NULL);

        purple_signal_connect(conversation, "sending-im-msg",
                                                plugin, PURPLE_CALLBACK(sending_im_msg_cb), NULL);

        purple_signal_connect(conversation, "conversation-created",
                                               plugin, PURPLE_CALLBACK(conversation_created_cb), plugin);

        purple_signal_connect(conversation, "receiving-im-msg",
                                               plugin, PURPLE_CALLBACK(receiving_im_msg_cb), NULL);

        purple_signal_connect(purple_blist_get_handle(), "blist-node-extended-menu",
                                               plugin, PURPLE_CALLBACK(blist_node_extended_menu_cb), NULL);


        purple_debug_misc("hka-plugin", "plugin-load\n");


        HKA.binary_to_text_encode = g_base64_encode;
        HKA.text_to_binary_decode = g_base64_decode;
        HKA.create_captcha = create_captcha;
        HKA.encode = simple_encode;
        HKA.decode = simple_decode;

        hka_initialize_buddy_variables(purple_blist_get_root());


        // crypto tests
        /*
        generate_diffie_hellman_keys(&pub, &priv);
        
        purple_debug_misc("hka-plugin", "plugin_load (pub key: %s )\n", pub);   
        purple_debug_misc("hka-plugin", "plugin_load (priv key: %s )\n", priv);   

        generate_diffie_hellman_keys(&pub2, &priv2);
        
        purple_debug_misc("hka-plugin", "plugin_load (pub key: %s )\n", pub2);   
        purple_debug_misc("hka-plugin", "plugin_load (priv key: %s )\n", priv2);   


        OPENSSL_free(priv);
        OPENSSL_free(pub); 
        OPENSSL_free(priv2);
        OPENSSL_free(pub2); 
        */

	return TRUE;
}


static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,							/**< magic			*/
	PURPLE_MAJOR_VERSION,							/**< major version	*/
	PURPLE_MINOR_VERSION,							/**< minor version	*/
	PURPLE_PLUGIN_STANDARD,							/**< type			*/
	NULL,									/**< ui_requirement	*/
	0,									/**< flags			*/
	NULL,									/**< dependencies	*/
	PURPLE_PRIORITY_DEFAULT,						/**< priority		*/

	"core-apachuta-hka",						        /**< id				*/
	N_("Human Key Agreement"),						/**< name			*/
	PACKAGE_VERSION,							/**< version		*/
	N_(""),                   	                                        /**< summary		*/
	N_(""),		                                                        /**< description	*/
	"Agnieszka Pachuta <pachuta.agnieszka@gmail.com>",			/**< author			*/
	PURPLE_WEBSITE,								/**< homepage		*/

	plugin_load,								/**< load			*/
	NULL,									/**< unload			*/
	NULL,									/**< destroy		*/

	NULL,									/**< ui_info		*/
	NULL,									/**< extra_info		*/
	NULL,								        /**< prefs_info		*/
	NULL,								        /**< actions		*/

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin) {
}

PURPLE_INIT_PLUGIN(hka, init_plugin, info)
