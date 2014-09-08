#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#include <internal.h>
#include <string.h>
#include <conversation.h>
#include <debug.h>
#include <plugin.h>
#include <request.h>
#include <signals.h>
#include <util.h>
#include <version.h>
#include <connection.h>
#include <notify.h>
#include <server.h>
#include <status.h>

#include <openssl/hmac.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "libcaptcha.h"

#define CHECK(x) if(0 == (x)) { error_msg( #x, __FILE__, __LINE__ );}

#define TAG_SIZE 32
#define IV_SIZE 16 // initialization vector size 
#define HASH_SIZE 32 // sha256


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

        // captcha
        void (*create_captcha)(gchar** imgData, gsize* imgSize, gchar** solution);

        // binary-to-text encoding
        gchar* (*binary_to_text_encode)(const gchar* data, gsize size);
        gchar* (*text_to_binary_decode)(const gchar* data, gsize* outSize);

        // UC-PAK and Covert-AKA protocols
        void (*generate_keys)(char** publicKey, char** privateKey);
        int (*generate_secret)(const char* receivedPublicKey, const char* publicKey, 
                const char* privateKey, char** secret);
        void (*create_mac)(const char* key, int keySize, const char* data, int dataSize, 
                char** tag, int* tagSize);
        int (*verify_mac)(const void *key, int keySize, const unsigned char *msg, int msgSize,
                const unsigned char *tag, int tagSize);
        void (*generate_random_iv)(char* buf, int num);

        // UC-PAK key encryption
        int (*encrypt_key)(const unsigned char* plaintext, const char* password, 
                const unsigned char *iv, unsigned char **ciphertext);
        void (*decrypt_key)(const char* ciphertext, int ciphertextSize, const char* password, 
                const char* iv, char** plaintextDec);
        
        // message encoding
        gchar* (*encode)(const gchar* key, const gchar* plaintext);
        gchar* (*decode)(const gchar* key, const gchar* ciphertext);
} HKA;


typedef struct __attribute__((__packed__)) {
        gchar tag;
        gchar id;
        gchar stringMsg[0];
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

typedef struct __attribute__ ((__packed__)) {
        gchar iv[IV_SIZE];
        gsize encodedMsgSize;
        gchar encodedMsg[0];
} EncodedMessage;


void error_msg(const char* arg, const char* file, int line)
{
        purple_debug_error("hka-plugin", "(Error: %s, line %d, %s)\n", file, line, arg); 
}

// ------------------------------------------------- crypto --------------------------------

char* BIG_PRIME = "29061604295055353424253889135036686149137613928445910579110547029313875439718550350988053475571612683327323345153327231211393015249645532776256400727289966400641306957507901234746498758025182038940679671682664254797692666182679379869976683486935708929913042514460763209045932503591749324455446799953688622329144696410730884066597340564332192788178741520134107078162110726238941776579522198478030817552964465684161208914242979565336565429929254106908575535379162804359248056067569743805576755474787518182630886631992744331412503393707482996568555663026991098873069831574888407838245872758683738640476645977988673820659";

char* GENERATOR = "2";

void create_diffie_hellman_object(DH** dh, const char* publicKey, const char* privateKey)
{
        BIGNUM* p = NULL;
        BIGNUM* g = NULL;
        BIGNUM* priv = NULL;
        BIGNUM* pub = NULL;
        char* gen;

        CHECK( BN_dec2bn(&p, BIG_PRIME) );
        CHECK( BN_dec2bn(&g, GENERATOR) );
     
        CHECK( *dh = DH_new() );
        (*dh)->p = p;
        (*dh)->g = g;
        if(publicKey != NULL)
        {
                CHECK( BN_dec2bn(&pub, publicKey) ); 
                (*dh)->pub_key = pub;   
        }
        if(privateKey != NULL)
        {
                CHECK( BN_dec2bn(&priv, privateKey) );
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
        CHECK( DH_generate_key(dh) );
        
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

        CHECK( *secret = (char*)malloc(sizeof(unsigned char) * (DH_size(dh))) );

        //zwraca wielkosc sekretu
        CHECK( secretSize = DH_compute_key(*secret, receivedPublicKeyBN, dh) );

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
      
        CHECK( HMAC(EVP_sha256(), key, keySize, msg, msgSize, newTag, &newTagSize) );
      
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


void rand_bytes(char* buf, int num)
{
        CHECK( RAND_bytes(buf, num) );
}

void openssl_init()
{
        // Initialise the library
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
}

void openssl_clean()
{
        EVP_cleanup();
        ERR_free_strings();
}

// h = H( iv || password)
BIGNUM* create_key_hash(const char* password, const unsigned char* iv)
{
        char* key;
        int keySize;
        char hash[HASH_SIZE];
        BIGNUM* hashBN = NULL;

        keySize = IV_SIZE + strlen(password);
        key = OPENSSL_malloc(keySize);
        memcpy(key, iv, IV_SIZE);
        memcpy(key + IV_SIZE, password, strlen(password));

        SHA256(key, keySize, hash);

        CHECK( hashBN = BN_bin2bn(hash, HASH_SIZE, NULL) );

        OPENSSL_free(key); 

        return hashBN;
}

int encrypt_mul(const unsigned char* plaintext, const char* password, const unsigned char *iv, unsigned char **ciphertext)
{
        BIGNUM* hashBN = NULL;
        BIGNUM* plaintextBN = NULL;
        BIGNUM* bigPrimeBN = NULL;
        BN_CTX* ctx = NULL;
        BIGNUM* ciphertextBN = NULL;
        int ciphertextSize;

        hashBN = create_key_hash(password, iv);

        CHECK( BN_dec2bn(&plaintextBN, plaintext) );

        CHECK( BN_dec2bn(&bigPrimeBN, BIG_PRIME) );

        ctx = BN_CTX_new();
        ciphertextBN = BN_new();

        CHECK( BN_mod_mul(ciphertextBN, plaintextBN, hashBN, bigPrimeBN, ctx) );

        *ciphertext = malloc(BN_num_bytes(ciphertextBN));

        CHECK( ciphertextSize = BN_bn2bin(ciphertextBN, *ciphertext) );

        BN_CTX_free(ctx);
        OPENSSL_free(ciphertextBN); 
        OPENSSL_free(hashBN);
        OPENSSL_free(plaintextBN);
        OPENSSL_free(bigPrimeBN);

        return ciphertextSize;
}

void decrypt_mul(const char* ciphertext, int ciphertextSize, const char* password, const char* iv, char** plaintextDec) 
{
        BIGNUM* hashBN = NULL;
        BIGNUM* ciphertextBN = NULL;
        BIGNUM* bigPrimeBN = NULL;
        BN_CTX* ctx = NULL;
        BN_CTX* ctx2 = NULL;
        BIGNUM* plaintextBN = NULL;
        BIGNUM* inverseBN = NULL;
        int plaintextSize;

        hashBN = create_key_hash(password, iv);

        CHECK( ciphertextBN = BN_bin2bn(ciphertext, ciphertextSize, NULL) ); 

        CHECK( BN_dec2bn(&bigPrimeBN, BIG_PRIME) );

        purple_debug_misc("hka-plugin", "decrypt_mul (start compute inverse)\n");

        // compute inverse
        ctx = BN_CTX_new();
        CHECK( inverseBN = BN_mod_inverse(NULL, hashBN, bigPrimeBN, ctx) );

        purple_debug_misc("hka-plugin", "decrypt_mul (inverse computed)\n");

        ctx2 = BN_CTX_new();
        plaintextBN = BN_new();

        // divide by the hash
        CHECK( BN_mod_mul(plaintextBN, ciphertextBN, inverseBN, bigPrimeBN, ctx2) );

        *plaintextDec = BN_bn2dec(plaintextBN);

        BN_CTX_free(ctx);
        BN_CTX_free(ctx2);
        OPENSSL_free(ciphertextBN); 
        OPENSSL_free(hashBN);
        OPENSSL_free(plaintextBN);
        OPENSSL_free(bigPrimeBN);
        OPENSSL_free(inverseBN);
}



int encrypt_aes_256(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
    const unsigned char *iv, unsigned char **ciphertext)
{
        EVP_CIPHER_CTX *ctx;

        int len;

        int ciphertext_len;

        /* Create and initialise the context */
        CHECK( ctx = EVP_CIPHER_CTX_new() );

        // Initialise the encryption operation
        CHECK( EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) );

        *ciphertext = (unsigned char*) malloc(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));

        /* Provide the message to be encrypted, and obtain the encrypted output.
        ** EVP_EncryptUpdate can be called multiple times if necessary
        **/
        CHECK( EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) );
        ciphertext_len = len;

        /* Finalise the encryption. Further ciphertext bytes may be written at
        ** this stage.
        **/
        CHECK( EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) );
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
}


int decrypt_aes_256(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
    const unsigned char *iv, unsigned char *plaintext)
{
        EVP_CIPHER_CTX *ctx;

        int len;

        int plaintext_len;

        /* Create and initialise the context */
        CHECK( ctx = EVP_CIPHER_CTX_new() );

        /* Initialise the decryption operation. IMPORTANT - ensure you use a key
        ** and IV size appropriate for your cipher
        ** In this example we are using 256 bit AES (i.e. a 256 bit key). The
        ** IV size for *most* modes is the same as the block size. For AES this
        ** is 128 bits */
        CHECK( EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) );

        /* Provide the message to be decrypted, and obtain the plaintext output.
        ** EVP_DecryptUpdate can be called multiple times if necessary
        **/
        CHECK( EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) );
        plaintext_len = len;

        /* Finalise the decryption. Further plaintext bytes may be written at
        ** this stage.
        **/
        CHECK( EVP_DecryptFinal_ex(ctx, plaintext + len, &len) );
        plaintext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
}

// ------------------------------------------------- crypto end ----------------------------



char* encode_aes_256(const char* key, const char* plaintext)
{
        unsigned char* ciphertext = NULL;
        int ciphertextSize;
        /* A 128 bit IV */
        unsigned char iv[IV_SIZE];
        int msgSize;
        EncodedMessage* msg;
        char* encodedMsg;

        // generate a random IV
        HKA.generate_random_iv(iv, IV_SIZE);

        // encrypt
        ciphertextSize = encrypt_aes_256(plaintext, strlen(plaintext), key, iv, &ciphertext);

        // prepare msg
        msgSize = sizeof(EncodedMessage) + ciphertextSize;
        msg = (EncodedMessage*) g_malloc(msgSize);
        msg->encodedMsgSize = ciphertextSize;
        memcpy(msg->encodedMsg, ciphertext, ciphertextSize);
        memcpy(msg->iv, iv, IV_SIZE);

        // encode msg
        encodedMsg = HKA.binary_to_text_encode((char*)msg, msgSize);

        g_free(ciphertext);
        g_free(msg);

        return encodedMsg;
}

char* decode_aes_256(const char* key, const char* stringMsg)
{
        DataMessage* dataMsg;
        gsize decodedDataSize;
        EncodedMessage* receivedMsg;
        char* plaintext;
        int plaintextSize;
        
        receivedMsg = (EncodedMessage*) HKA.text_to_binary_decode(stringMsg, &decodedDataSize);

        plaintext = (unsigned char*)malloc(receivedMsg->encodedMsgSize + 1); // plaintext is no longer than ciphertext

        plaintextSize = decrypt_aes_256(receivedMsg->encodedMsg, receivedMsg->encodedMsgSize, key, receivedMsg->iv, plaintext);
        plaintext[plaintextSize] = 0;

        return plaintext;
}

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
hka_set_dh_secret(PurpleBuddy* buddy, const gchar* secret)
{
        purple_blist_node_set_string((PurpleBlistNode*) buddy, "hka-dh-secret", secret);
}

static const gchar*
hka_get_dh_secret(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-dh-secret"); 
}




static void
hka_reset_variables(PurpleBuddy* buddy)
{
        hka_set_synchronized(buddy, FALSE); 

        //hka_set_session_key((PurpleBuddy*) node, NULL);
}

static void
hka_init_message(PurpleBuddy* buddy) 
{
        const char* initMsg = " The user is trying to establish an encrypted connection using the Human Key Agreement protocol.\n \
        You can download the plugin from https://github.com/apachuta/pidgin_plugin";

        hka_reset_variables(buddy);
        hka_send_text(buddy, INIT, initMsg);
        hka_set_protocol_state(buddy, INIT_RESPONSE);

        purple_debug_misc("hka-plugin", "hka_init_message (hka-protocol-state = %c)\n", 
                          hka_get_protocol_state(buddy)); 
}

static void
hka_init_message_response(PurpleBuddy* buddy) 
{
        hka_reset_variables(buddy);
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

static void 
hka_show_reset_confirmation(PurpleBuddy* buddy)
{
        PurplePlugin* plugin;
        const gchar* buddyName = purple_buddy_get_alias(buddy);
        char* primaryInfo = g_strdup_printf("The connection with %s is already secure. Do you want to establish a secure key again?", buddyName);

        plugin = purple_plugins_find_with_id("core-apachuta-hka");
  
        purple_debug_misc("hka-plugin", "hka_show_reset_confirmation (primaryInfo = %s)\n", primaryInfo);

        purple_request_action ( 
        plugin, // handle
        "Human Key Agreement", // title
        primaryInfo, // primary
        NULL, // secondary
        0, // default action index
        NULL, // PurpleAccount
        "Qwerty", // the username of the buddy associated with the reqest (char*)
        NULL, // PurpleConversation
        buddy, // data to pass to the callback
        2, // number of actions
        _("_OK"), // action
        G_CALLBACK(hka_init_message),  // callback
        _("_Cancel"), //action2
        NULL //callback2
        ); 

        g_free(primaryInfo);

}

// Universally-Composable Password Authenticated Key Exchange UC-PAK

static void
hka_UC_PAK_step0(PurpleBuddy* buddy) 
{
        char* publicKey;
        char* privateKey;

        // generate DH keys
        HKA.generate_keys(&publicKey, &privateKey);
        
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
        char* publicKey;
        char* privateKey;
        const char* password;
        unsigned char iv[IV_SIZE];
        unsigned char* ciphertext; 
        int ciphertextSize;
        char* secret;
        int secretSize;
        char* encodedSecret;

        EncryptedKeyMessage* msg;
        int msgSize;


        // generate DH keys
        HKA.generate_keys(&publicKey, &privateKey);
        
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (pub key: %s )\n", publicKey);   
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (priv key: %s )\n", privateKey);    

        // create and set DH secret 
        secretSize = HKA.generate_secret(receivedPublicKey, publicKey, privateKey, &secret);
        encodedSecret = HKA.binary_to_text_encode(secret, secretSize);
        hka_set_dh_secret(buddy, encodedSecret);

        purple_debug_misc("hka-plugin", "hka_UC_PAK_step1 (secretSize: %d )\n", secretSize);

        // Generate a random IV
        HKA.generate_random_iv(iv, IV_SIZE);

        // encrypt public key with password
        password = hka_get_password(buddy);
        ciphertextSize = HKA.encrypt_key(publicKey, password, iv, &ciphertext);
 
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
        
        g_free(ciphertext);
        g_free(publicKey);
        g_free(privateKey);
        g_free(msg);      
        g_free(secret);
        g_free(encodedSecret);   
}

static void
hka_UC_PAK_step2(PurpleBuddy* buddy, const gchar* stringMsg) 
{
        DataMessage* dataMsg; 
        EncryptedKeyMessage* receivedMsg;
        gsize decodedDataSize;
        char* receivedKey;
        int receivedKeySize;
        const char* password;
        char* secret;
        int secretSize;
        char* encodedSecret;
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
        
        HKA.decrypt_key(receivedMsg->encryptedKey, receivedMsg->encryptedKeySize, password, receivedMsg->iv, &receivedKey); 

        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (received and encrypted public key: %s )\n", receivedKey);

        // create and set DH secret
        privateKey = hka_get_dh_private_key(buddy);
        publicKey = hka_get_dh_public_key(buddy);       
        secretSize = HKA.generate_secret(receivedKey, publicKey, privateKey, &secret);
        encodedSecret = HKA.binary_to_text_encode(secret, secretSize);
        hka_set_dh_secret(buddy, encodedSecret);

        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (public key: %s )\n", publicKey);
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (private key: %s )\n", privateKey); 
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (secret size: %d )\n", secretSize);

        // Covered AKA step 0 ---------------------------------------------------------------

        // generate new DH keys
        HKA.generate_keys(&publicKey2, &privateKey2);
        
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (new pub key: %s )\n", publicKey2);   
        purple_debug_misc("hka-plugin", "hka_UC_PAK_step2 (new priv key: %s )\n", privateKey2);   

        // set new DH keys
        hka_set_dh_public_key(buddy, publicKey2);
        hka_set_dh_private_key(buddy, privateKey2);

        // create public key tag (with a DH secret as a key)
        HKA.create_mac(secret, secretSize, publicKey2, strlen(publicKey2), &tag, &tagSize);

        if(HKA.verify_mac(secret, secretSize, publicKey2, strlen(publicKey2), tag, tagSize))
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


        hka_set_protocol_state(buddy, COVERT_AKA_1); 

        g_free(dataMsg);
        g_free(receivedKey);
        g_free(encodedSecret);

        g_free(privateKey2);
        g_free(publicKey2);
        g_free(secret);
        g_free(msg);
}

// Covert Authenticated Key Agreement Covert-AKA

void hka_covert_AKA_step1(PurpleBuddy* buddy, const gchar* stringMsg)
{
        DataMessage* dataMsg;
        gsize decodedDataSize;
        PublicKeyTagMessage* receivedMsg;
        const char* encodedSecret;
        char* secret;
        gsize secretSize;
        char* publicKey2;
        char* privateKey2;
        char* tag;
        int tagSize;
        int msgSize;
        PublicKeyTagMessage* msg;
        char* sessionKey;
        int sessionKeySize;
        char* encodedSessionKey;
               
        dataMsg = (DataMessage*) HKA.text_to_binary_decode(stringMsg, &decodedDataSize);
        receivedMsg = (PublicKeyTagMessage*) dataMsg->data;

        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (received public key: %s )\n", receivedMsg->publicKey);

        // generate new DH keys
        HKA.generate_keys(&publicKey2, &privateKey2);
        
        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (new pub key: %s )\n", publicKey2);   
        purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (new priv key: %s )\n", privateKey2);   

        // create public key tag (with a DH secret as a key)
        encodedSecret = hka_get_dh_secret(buddy);
        secret = HKA.text_to_binary_decode(encodedSecret, &secretSize);        
        HKA.create_mac(secret, secretSize, publicKey2, strlen(publicKey2), &tag, &tagSize);
        

        // prepare data to send
        msgSize = sizeof(PublicKeyTagMessage) + strlen(publicKey2) + 1;  // null terminator
        msg = (PublicKeyTagMessage*) g_malloc(msgSize);
        msg->publicKeySize = strlen(publicKey2);
        memcpy(msg->tag, tag, TAG_SIZE);
        memcpy(msg->publicKey, publicKey2, strlen(publicKey2) + 1); 

        // send message
        hka_send_data(buddy, COVERT_AKA_1, (gchar*)msg, msgSize); 


        // verify received message and tag with created secret
        if(HKA.verify_mac(secret, secretSize, receivedMsg->publicKey, receivedMsg->publicKeySize, receivedMsg->tag, TAG_SIZE))
        {
                purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (tag verification positive (with received PK and my secret))\n");   
                
                sessionKeySize = HKA.generate_secret(receivedMsg->publicKey, publicKey2, privateKey2, &sessionKey);
                encodedSessionKey = HKA.binary_to_text_encode(sessionKey, sessionKeySize);
                hka_set_session_key(buddy, encodedSessionKey);
                hka_set_protocol_state(buddy, FINISHED);
                hka_show_protocol_success_info(buddy);
         
                g_free(sessionKey);
                g_free(encodedSessionKey);

        }
        else
        {
                purple_debug_misc("hka-plugin", "hka_covert_AKA_step1 (tag verification negative (with received PK and my secret))\n");
                hka_set_session_key(buddy, NULL);
                hka_set_protocol_state(buddy, INIT);
                hka_show_protocol_failure_info(buddy);
        }
        
        
        g_free(dataMsg);
        g_free(privateKey2);
        g_free(publicKey2);
        g_free(secret);
        g_free(msg);
}

void hka_covert_AKA_step2(PurpleBuddy* buddy, const gchar* stringMsg)
{
        DataMessage* dataMsg;
        gsize decodedDataSize;
        PublicKeyTagMessage* receivedMsg;
        const char* encodedSecret;
        char* secret;
        gsize secretSize;
        char* sessionKey;
        int sessionKeySize;
        char* encodedSessionKey;
        const char* publicKey;
        const char* privateKey;

        dataMsg = (DataMessage*) HKA.text_to_binary_decode(stringMsg, &decodedDataSize);
        receivedMsg = (PublicKeyTagMessage*) dataMsg->data;

        purple_debug_misc("hka-plugin", "hka_covert_AKA_step2 (received public key: %s )\n", receivedMsg->publicKey);

        // get secret
        encodedSecret = hka_get_dh_secret(buddy);
        secret = HKA.text_to_binary_decode(encodedSecret, &secretSize);        

        // verify received message and tag with created secret
        if(HKA.verify_mac(secret, secretSize, receivedMsg->publicKey, receivedMsg->publicKeySize, receivedMsg->tag, TAG_SIZE))
        {
                purple_debug_misc("hka-plugin", "hka_covert_AKA_step2 (tag verification positive (with received PK and my secret))\n");
                
                publicKey = hka_get_dh_public_key(buddy);
                privateKey = hka_get_dh_private_key(buddy);
 
                sessionKeySize = HKA.generate_secret(receivedMsg->publicKey, publicKey, privateKey, &sessionKey);
                encodedSessionKey = HKA.binary_to_text_encode(sessionKey, sessionKeySize);
                hka_set_session_key(buddy, encodedSessionKey);
                hka_set_protocol_state(buddy, FINISHED);
                hka_show_protocol_success_info(buddy);

                g_free(sessionKey);
                g_free(encodedSessionKey);
        }
        else
        {
                purple_debug_misc("hka-plugin", "hka_covert_AKA_step2 (tag verification negative (with received PK and my secret))\n");
                hka_set_session_key(buddy, NULL);
                hka_set_protocol_state(buddy, INIT);
                hka_show_protocol_failure_info(buddy);
        } 

        g_free(secret);
        g_free(dataMsg);
}

static void
hka_captcha_cb(PurpleBuddy* buddy, const gchar* solution) 
{
        gchar state;
        gchar* oldPassword; 

        state = hka_get_protocol_state(buddy); 
        oldPassword = g_strdup_printf("%s", hka_get_password(buddy));

        purple_debug_misc("hka-plugin", "hka_captcha_cb (solution = %s)\n", solution);

        if(state == SEND_CAPTCHA_RESPONSE) { 
                hka_create_and_set_password(buddy, oldPassword, solution);
                
                hka_UC_PAK_step0(buddy);

        }  
        else if(state == UC_PAK_0) {

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
        gchar* smallText = "The connecton will not be secure unless you get confirmation.";
        gchar state;

        state = hka_get_protocol_state(buddy); 

        buddyName = purple_buddy_get_alias(buddy); 

        if(state == SEND_CAPTCHA_RESPONSE) { 
                text = g_strdup_printf("Establish a secure connection with %s. Solve Captcha", buddyName);

        }  
        else if(state == UC_PAK_0) { 
                text = g_strdup_printf("%s wants to establish a secure connection. Solve Captcha.", buddyName);
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
                         _(smallText), 
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

        // you can start a protocol in any state
        if(msg->tag == SPECIAL_TAG && msg->id == INIT) {
                purple_debug_misc("hka-plugin", "receiving_im_msg_cb (INIT)\n");
                hka_init_message_response(buddy); 
                return TRUE; // do not display the message
        }
                
        if(msg->tag == SPECIAL_TAG && msg->id == state) {
                
                if(state == INIT_RESPONSE) {
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
        
        // Ignore invalid message
        if(msg->tag == SPECIAL_TAG && msg->id != state) {
                 purple_debug_misc("hka-plugin", "receiving_im_msg_cb (invalid, waiting for: %c, received: %c)\n", state, msg->id); 
                 return TRUE; //do not display the message
        }
         
        // display normal message (not from the protocol)
        return FALSE;
}


// extended menu
static void
hka_start_protocol_cb(PurpleBlistNode* node, gpointer data)
{
        gchar state; 
        PurpleBuddy* buddy;

        if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
                return;

        buddy = (PurpleBuddy*) node;
        state = hka_get_protocol_state(buddy);

        purple_debug_misc("hka-plugin", "hka_start_protocol_cb (hka-protocol-state = %c)\n", state);
 
        if(state == FINISHED) 
        {
                purple_debug_misc("hka-plugin", "hka_start_protocol_cb (state FINISHED, session key = %s)\n", hka_get_session_key(buddy));
                hka_show_reset_confirmation(buddy);
        }
        else // state == INIT or other
        {
                hka_init_message(buddy);
        }
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
        bna = purple_menu_action_new(_("Establish a secure key"), PURPLE_CALLBACK(hka_start_protocol_cb), NULL, NULL);
        *m = g_list_append(*m, bna); 
}

static void
hka_initialize_buddy_variables(PurpleBlistNode* node) 
{
        gchar state;
        PurpleBuddy* buddy;

        if(node == NULL)
                return;

        if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
                buddy = (PurpleBuddy*) node;

                if(hka_get_session_key(buddy) == NULL) 
                {      
                        hka_set_protocol_state(buddy, INIT);
                }
                else {
                        hka_set_protocol_state(buddy, FINISHED);
                }
                 
                hka_reset_variables(buddy);        
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

        openssl_init();
       
        // captcha
        HKA.create_captcha = create_captcha;
 
        // binary-to-text encoding
        HKA.binary_to_text_encode = g_base64_encode;
        HKA.text_to_binary_decode = g_base64_decode;
               
        // UC-PAK and Covert-AKA protocols
        HKA.generate_keys = generate_diffie_hellman_keys;
        HKA.generate_secret = generate_diffie_hellman_secret;
        HKA.create_mac = hmac_sha256;
        HKA.verify_mac = hmac_sha256_vrfy; 
        HKA.generate_random_iv = rand_bytes;

        // UC-PAK key encription
        HKA.encrypt_key = encrypt_mul;
        HKA.decrypt_key = decrypt_mul; 
         
        // message encoding 
        HKA.encode = encode_aes_256; 
        HKA.decode = decode_aes_256; 

        hka_initialize_buddy_variables(purple_blist_get_root());

	return TRUE;
}


static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,							/**< magic		*/
	PURPLE_MAJOR_VERSION,							/**< major version	*/
	PURPLE_MINOR_VERSION,							/**< minor version	*/
	PURPLE_PLUGIN_STANDARD,							/**< type		*/
	NULL,									/**< ui_requirement	*/
	0,									/**< flags		*/
	NULL,									/**< dependencies	*/
	PURPLE_PRIORITY_DEFAULT,						/**< priority		*/

	"core-apachuta-hka",						        /**< id			*/
	N_("Human Key Agreement"),						/**< name		*/
	PACKAGE_VERSION,							/**< version		*/
	N_(""),                   	                                        /**< summary		*/
	N_(""),		                                                        /**< description	*/
	"Agnieszka Pachuta <pachuta.agnieszka@gmail.com>",			/**< author		*/
	PURPLE_WEBSITE,								/**< homepage		*/

	plugin_load,								/**< load		*/
	NULL,									/**< unload		*/
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
