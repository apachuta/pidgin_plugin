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

const gchar INIT = 65;
const gchar INIT_RESPONSE = 66;
const gchar SEND_CAPTCHA = 67;
const gchar SEND_CAPTCHA_RESPONSE = 68;
const gchar UC_PAK_0 = 69;
const gchar UC_PAK_1 = 70;

const gchar FINISHED = 80;

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

static const gchar*
hka_get_protocol_state(PurpleBuddy* buddy)
{
        return purple_blist_node_get_string((PurpleBlistNode*) buddy, "hka-protocol-state");
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
hka_init_message(PurpleBuddy* buddy) 
{
        hka_send_text(buddy, INIT, " Nie masz mojego super pluginu :(");
        hka_set_protocol_state(buddy, INIT_RESPONSE);

        purple_debug_misc("hka-plugin", "hka_init_message (hka-protocol-state = %s)\n", 
                          hka_get_protocol_state(buddy)); 
}

static void
hka_init_message_response(PurpleBuddy* buddy) 
{
        hka_send_text(buddy, INIT_RESPONSE, " ");
        hka_set_protocol_state(buddy, SEND_CAPTCHA);

        purple_debug_misc("hka-plugin", "hka_init_message_response (hka-protocol-state = %s)\n", 
                          hka_get_protocol_state(buddy)); 
}

static void
hka_send_captcha(PurpleBuddy* buddy)
{
        purple_debug_misc("hka-plugin", "hka_send_captcha (beginning)\n");

        gchar* imgData;
        gsize imgSize;

        HKA.create_captcha(&imgData, &imgSize);
        hka_set_password(buddy, "aaa"); //TODO niech create_captcha podaje rozwiazanie. wpisac je tutaj

        hka_send_data(buddy, SEND_CAPTCHA, imgData, imgSize);
        hka_set_protocol_state(buddy, SEND_CAPTCHA_RESPONSE);

        g_free(imgData);

        purple_debug_misc("hka-plugin", "hka_send_captcha (hka-protocol-state = %s)\n", 
                          hka_get_protocol_state(buddy));
}

static void
hka_send_captcha_response(PurpleBuddy* buddy)
{
        purple_debug_misc("hka-plugin", "hka_send_captcha_response (beginning)\n");

        gchar* imgData;
        gsize imgSize;

        HKA.create_captcha(&imgData, &imgSize);
        hka_set_password(buddy, "aaa"); //TODO niech create_captcha podaje rozwiazanie. wpisac je tutaj

        hka_send_data(buddy, SEND_CAPTCHA_RESPONSE, imgData, imgSize);
        hka_set_protocol_state(buddy, UC_PAK_0);  // Test mode !!!

        g_free(imgData);

        purple_debug_misc("hka-plugin", "hka_send_captcha (hka-protocol-state = %s)\n", 
                          hka_get_protocol_state(buddy));
}

// Universally-Composable Password Authenticated Key Exchange UC-PAK

static void
hka_UC_PAK_step0(PurpleBuddy* buddy) 
{
        const gchar* password = hka_get_password(buddy);

        //testmode!!
        hka_send_text(buddy, UC_PAK_0, password);
        hka_set_protocol_state(buddy, UC_PAK_1);
}

static void
hka_UC_PAK_step1(PurpleBuddy* buddy, const gchar* msg)
{
        const gchar* password = hka_get_password(buddy);

        //testmode!!
        hka_set_key(buddy, msg);
        hka_set_session_key(buddy, msg);

        hka_send_text(buddy, UC_PAK_1, password);
        hka_set_protocol_state(buddy, FINISHED);
}

static void
hka_UC_PAK_step2(PurpleBuddy* buddy, const gchar* msg) {
        //testmode!!
        hka_set_key(buddy, msg);
        hka_set_session_key(buddy, msg);

        hka_set_protocol_state(buddy, FINISHED);
}



static void
hka_solved_captcha_cb(PurpleBuddy* buddy, PurpleRequestFields* fields) 
{
        const gchar* state;
        const gchar* solution;
        gchar* oldPassword; 

        state = hka_get_protocol_state(buddy); 
        solution = purple_request_fields_get_string(fields, "solution");
        oldPassword = g_strdup_printf("%s", hka_get_password(buddy));


        purple_debug_misc("hka-plugin", "hka_solved_captcha_cb (solution = %s)\n", solution);

        if(*state == SEND_CAPTCHA_RESPONSE) { //test mode !!
                hka_create_and_set_password(buddy, oldPassword, solution);
                
                hka_UC_PAK_step0(buddy);

        }  
        else if(*state == UC_PAK_0) { //test mode !!

                hka_create_and_set_password(buddy, solution, oldPassword);

                if(hka_synchronized(buddy)) {
                        purple_debug_misc("hka-plugin", "hka_solved_captcha_cb (is synchronized)\n");
                        hka_set_synchronized(buddy, FALSE);
                        
                        hka_UC_PAK_step1(buddy, hka_get_synchronized_msg(buddy));

                }
                else {
                        purple_debug_misc("hka-plugin", "hka_solved_captcha_cb (is not synchronized)\n");
                        hka_set_synchronized(buddy, TRUE);
                }
        }

        g_free(oldPassword);

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
                         N_("CAPTCHA"), 
                         _("Solve captcha"), 
                         NULL, 
                         request, 
                         _("_Set"), G_CALLBACK(hka_solved_captcha_cb), 
                         _("_Cancel"), NULL, 
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
        PurpleBuddy* buddy;
        const gchar* state;
        Message* msg; 
        
        msg = (Message*) *buffer;
        buddy = purple_find_buddy(account, *sender);
        state = hka_get_protocol_state(buddy); 

        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (beggining, hka-protocol-state = %s, msg->id = %c, strlen(*buffer) = %d, password = %s)\n", state, msg->id, strlen(*buffer), hka_get_password(buddy)); 

        if(msg->tag == SPECIAL_TAG && msg->id == *state) {
                if(*state == INIT) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (INIT)\n");
                        hka_init_message_response(buddy); 
                }
                else if(*state == INIT_RESPONSE) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (INIT_RESPONSE)\n");
                        hka_send_captcha(buddy); 
                }
                else if(*state == SEND_CAPTCHA) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (SEND_CAPTCHA)\n");
                        hka_send_captcha_response(buddy);
                        hka_show_captcha(msg->stringMsg, buddy);         
                }          
                else if(*state == SEND_CAPTCHA_RESPONSE) {
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (SEND_CAPTCHA_RESPONSE)\n");
                        hka_show_captcha(msg->stringMsg, buddy);
                        //hka_set_protocol_state(buddy, UC_PAK_0); // testmode !!! 

                }
                else if(*state == UC_PAK_0 ) {  //testmode !!!
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
                else if(*state == UC_PAK_1 ) {  //testmode !!!
                        purple_debug_misc("hka-plugin", "receiving_im_msg_cb (UC_PAK_1)\n");
                        hka_UC_PAK_step2(buddy, msg->stringMsg); 
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
        const gchar* state; 

        if(!PURPLE_BLIST_NODE_IS_BUDDY(node))
                return;

        state = hka_get_protocol_state((PurpleBuddy*) node);

        purple_debug_misc("hka-plugin", "hka_start_protocol_cb (hka-protocol-state = %s)\n", 
                          state);

        if(*state == INIT)
                hka_init_message((PurpleBuddy*) node);
        else if(*state == FINISHED) 
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
        gchar* state;

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

        hka_initialize_buddy_variables(purple_blist_get_root());

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
