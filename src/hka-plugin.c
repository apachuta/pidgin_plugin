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

struct _hka_protocol {

        //captcha
        void (*create_captcha)(gchar** imgData, gsize* imgSize);

        //binary-to-text encoding
        gchar* (*binary_to_text_encode)(const gchar* data, gsize size);
        gchar* (*text_to_binary_decode)(const gchar* data, gsize* outSize);

} HKA;


typedef struct __attribute__((__packed__)) {
        gchar tag;
        gint id;
} _header;

typedef struct __attribute__((__packed__)) {
        _header header;
        gsize size;
        gchar data[0];
} _message;



static void
hka_send(PurpleConversation *conv, int id, const gchar* data, gsize dataSize) 
{
        gchar* encodedMsg;
        gsize msgSize = sizeof(_message) + dataSize;
        _message* msg = (_message*) g_malloc(msgSize);
        
        msg->header.tag = 0x01;
        msg->header.id = id;
        msg->size = dataSize;
        
        memcpy(msg->data, data, dataSize);

        encodedMsg = HKA.binary_to_text_encode((gchar*)msg, msgSize);

        purple_conv_im_send(PURPLE_CONV_IM(conv), encodedMsg);

        g_free(msg);
        g_free(encodedMsg);
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
       hka_send(conv, 1, "lalala", 6);
}


static gboolean
receiving_im_msg_cb(PurpleAccount *account, char **sender, char **buffer,
                                     PurpleConversation *conv, PurpleMessageFlags *flags, void *data)
{
      
        return FALSE;
}



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

        purple_debug_misc("hka", "plugin-load - EMPTY PLUGIN\n");


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
