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

const gchar SPECIAL_TAG = 126;

const gchar INIT = 33;
const gchar INIT_RESPONSE = 34;
const gchar SEND_CAPTCHA = 35;
const gchar SEND_CAPTCHA_RESPONSE = 36;

struct HumanKeyAgreementProtocol {

        //captcha
        void (*create_captcha)(gchar** imgData, gsize* imgSize);

        //binary-to-text encoding
        gchar* (*binary_to_text_encode)(const gchar* data, gsize size);
        gchar* (*text_to_binary_decode)(const gchar* data, gsize* outSize);

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

        g_free(msg);

}

static void
hka_send(PurpleBuddy* buddy, gchar id, const gchar* data, gsize dataSize)
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


/*
static void
hka_send(PurpleConversation *conv, gchar id, const gchar* data, gsize dataSize) 
{
        gchar* encodedMsg;
        gsize msgSize = sizeof(Message) + dataSize;
        Message* msg = (Message*) g_malloc(msgSize);
        
        msg->header.tag = SPECIAL_TAG;
        msg->header.id = id;
        msg->size = dataSize;
        
        memcpy(msg->data, data, dataSize);

        encodedMsg = HKA.binary_to_text_encode((gchar*)msg, msgSize);

        purple_conv_im_send(PURPLE_CONV_IM(conv), (gchar*)msg); //encodedMsg);

        g_free(msg);
        g_free(encodedMsg);
}


static void
hka_send_text(PurpleConversation *conv, gchar id, const gchar* text) 
{
        gsize textSize = strlen(text);
        gsize msgSize = sizeof(TextMessage) + textSize;
        TextMessage* textMsg = (TextMessage*) g_malloc(msgSize);
        gchar* encodedTag = HKA.binary_to_text_encode(&SPECIAL_TAG, 1);
        gchar* encodedId = HKA.binary_to_text_encode(&id, 1);

        textMsg->header.tag = *encodedTag;
        textMsg->header.id = *encodedId;
        
        strcpy(textMsg->text, text);
        
        purple_conv_im_send(PURPLE_CONV_IM(conv), (gchar*) textMsg); 
  
        g_free(textMsg);
        g_free(encodedTag);
        g_free(encodedId);
}

*/

static void
load_image(gchar** imgData, gsize* imgSize) {
        char* filename;
        filename = "/home/agnieszka/captcha.gif";
        g_file_get_contents(filename, imgData, imgSize, NULL);
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

}

static void
conversation_created_cb(PurpleConversation *conv, gpointer handle) //void *data)
{ 
      
}


static gboolean
receiving_im_msg_cb(PurpleAccount *account, char **sender, char **buffer,
                                     PurpleConversation *conv, PurpleMessageFlags *flags, void *data)
{
        
/*
        Message* msg = (Message*) *buffer;
        gchar* state = (gchar*) purple_conversation_get_data(conv, "hka-protocol-state");

        if(msg->tag == SPECIAL_TAG && msg->id == *state) {
                //if()




                return TRUE;
        }
*/
         
        return FALSE;
}


static void
hka_start_protocol_cb(PurpleBlistNode *node, gpointer data)
{
        PurpleBuddy* buddy;

        if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
                return;

        buddy = (PurpleBuddy*) node;

        hka_send_text(buddy, INIT, " Nie masz mojego super pluginu :(");

/*
        int buddyInt;
        buddyInt = purple_blist_node_get_int(node, "buddy-int");
        buddyInt++;
        purple_blist_node_set_int(node, "buddy-int", buddyInt);

        purple_debug_misc("kiss test", "start_protocol_cb (buddy-int = %d)\n", buddyInt); 

*/
}
 


// extended menu
static void
blist_node_extended_menu_cb(PurpleBlistNode *node, GList **m)
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



// LOAD
static gboolean
plugin_load(PurplePlugin *plugin)
{
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
        HKA.create_captcha = load_image;


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
