// Helper program to generate a new secret for use in two-factor
// authentication.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

#include <stdio.h>

#include <gtk/gtk.h>
#include <glib/gprintf.h>

#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define BITS_PER_BASE32_CHAR      5           // Base32 expands space by 8/5

#define KEY_STR_LEN 16

#define DEBUG

typedef struct mydata {
  GtkWidget *window;
  GtkWidget *grid;
  //GtkWidget *label;
  char key_str[KEY_STR_LEN + 1];
  GtkWidget *status_bar;
} MYDATA;

#define MAX_ACCOUNTS 5

MYDATA mydata[MAX_ACCOUNTS];

MYDATA mydata2[1];

int correct_code;

unsigned int mydata_index = 0;

static int generateCode(const char *key, unsigned long tm) {
  uint8_t challenge[8];
  for (int i = 8; i--; tm >>= 8) {
    challenge[i] = tm;
  }


  // Estimated number of bytes needed to represent the decoded secret. Because
  // of white-space and separators, this is an upper bound of the real number,
  // which we later get as a return-value from base32_decode()
  int secretLen = (strlen(key) + 7)/8*BITS_PER_BASE32_CHAR;

  // Sanity check, that our secret will fixed into a reasonably-sized static
  // array.
  if (secretLen <= 0 || secretLen > 100) {
    return -1;
  }

  // Decode secret from Base32 to a binary representation, and check that we
  // have at least one byte's worth of secret data.
  uint8_t secret[100];
  if ((secretLen = base32_decode((const uint8_t *)key, secret, secretLen))<1) {
    return -1;
  }

  // Compute the HMAC_SHA1 of the secret and the challenge.
  uint8_t hash[SHA1_DIGEST_LENGTH];
  hmac_sha1(secret, secretLen, challenge, 8, hash, SHA1_DIGEST_LENGTH);

  // Pick the offset where to sample our hash value for the actual verification
  // code.
  const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;

  // Compute the truncated hash in a byte-order independent loop.
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }

  // Truncate to a smaller number of digits.
  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= VERIFICATION_CODE_MODULUS;

  return truncatedHash;
}

static void
calculate_code (GtkWidget *widget,
                gpointer   data)
{
  unsigned long tm;
  int step_size = 30;
  char buf[128];
  int expires;
  GtkClipboard *clipboard;

  MYDATA *mydata = data;

  //GtkWidget *window = mydata->window;
  //GtkWidget *grid = mydata->grid;
  //GtkWidget *label = mydata->label;
  //char *key_str = mydata->key_str;

  tm = time(NULL)/(step_size ? step_size : 30);
  //int correct_code = generateCode("JBSWY3DPEHPK3PXP", tm);
#ifdef DEBUG
g_printf("%s::key_str:%s\n", __FUNCTION__, mydata->key_str);
#endif
  correct_code = generateCode(mydata->key_str, tm);

  /* Get the clipboard object and copies correct_code in clipboard */
  //snprintf(buf, 128, "%06d", correct_code );
  //clipboard = gtk_clipboard_get (GDK_SELECTION_CLIPBOARD);
  //gtk_clipboard_set_text (clipboard, buf, -1);

  expires = step_size - (time(NULL) % (step_size ? step_size : 30));
  snprintf(buf, 128, "The token is %03d %03d and expires in %02ds.", correct_code / 1000,
              correct_code - ((correct_code / 1000) * 1000), expires);
  //gtk_label_set_text(GTK_LABEL(label), buf);
  gtk_statusbar_push(GTK_STATUSBAR(mydata->status_bar), 1, buf);
}

static void
new_account (GtkWidget *widget,
             gpointer   data)
{
  GtkWidget *btn;
  GtkWidget *wnd;
  GtkWidget *lbl_account;
  GtkWidget *entry_account;
  GtkWidget *lbl_key;
  GtkWidget *entry_key;
  GtkWidget *acc_grid;
  GtkWidget *box_dialog;

  MYDATA *mydata = data;

  if (mydata_index > (MAX_ACCOUNTS - 1)) {
    char buf[128];
    snprintf(buf, 128, "The maximum number of accounts is %d", MAX_ACCOUNTS);
    //gtk_label_set_text(GTK_LABEL(label), buf);
    gtk_statusbar_push(GTK_STATUSBAR(mydata->status_bar), 1, buf);
    return;
  }

  wnd = gtk_dialog_new_with_buttons("Enter account data", GTK_WINDOW(mydata->window), GTK_DIALOG_MODAL, "OK", 1, "Cancel", 2, NULL);
  box_dialog = gtk_dialog_get_content_area(GTK_DIALOG(wnd));
  lbl_account = gtk_label_new ("Account name ");
  gtk_widget_show (lbl_account);
  gtk_box_pack_start (GTK_BOX(box_dialog), lbl_account, TRUE, TRUE, 5);

  entry_account = gtk_entry_new();
  gtk_widget_show (entry_account);
  gtk_box_pack_start (GTK_BOX(box_dialog), entry_account, TRUE, TRUE, 5);

  lbl_key = gtk_label_new ("Account key ");
  gtk_widget_show (lbl_key);
  gtk_box_pack_start (GTK_BOX(box_dialog), lbl_key, TRUE, TRUE, 5);

  entry_key = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(entry_key), KEY_STR_LEN);
  gtk_widget_show (entry_key);
  gtk_box_pack_start (GTK_BOX(box_dialog), entry_key, TRUE, TRUE, 5);

  int reply = gtk_dialog_run(GTK_DIALOG(wnd));

  switch (reply) {
    case 1:
#ifdef DEBUG
g_printf("%s::OK\n", __FUNCTION__);
#endif
      ; // Compiler does not allow keyword const after #endif
      const gchar *entry_key_text = gtk_entry_get_text(GTK_ENTRY(entry_key));
      strncpy(mydata[mydata_index].key_str, entry_key_text, KEY_STR_LEN);

      const gchar *entry_account_text = gtk_entry_get_text(GTK_ENTRY(entry_account));

      btn = gtk_button_new_with_label (entry_account_text);
      gtk_widget_show (btn);

      mydata[mydata_index].window = mydata->window;
      mydata[mydata_index].grid = mydata->grid;
      mydata[mydata_index].status_bar = mydata->status_bar;
      //mydata[mydata_index].label = mydata->label;

      char buf1[128];
      snprintf(buf1, 128, "Added account %s", entry_account_text);
      gtk_statusbar_push(GTK_STATUSBAR(mydata->status_bar), 1, buf1);

      g_signal_connect (btn, "clicked", G_CALLBACK (calculate_code), &mydata[mydata_index]);

      mydata_index += 1;

      gtk_grid_insert_next_to(GTK_GRID(mydata->grid), mydata->status_bar, GTK_POS_TOP);
      gtk_grid_attach_next_to(GTK_GRID(mydata->grid), btn, mydata->status_bar, GTK_POS_TOP, 3, 1);

      break;

    case 2:
#ifdef DEBUG
g_printf("%s::Cancel\n", __FUNCTION__);
#endif
      break;
  }

  gtk_widget_destroy(wnd);
}

static void
clipboard_clicked (GtkWidget *widget,
                   gpointer   data)
{
  unsigned long tm;
  int step_size = 30;
  char buf[128];
  GtkClipboard *clipboard;

  MYDATA *mydata2 = data;

#ifdef DEBUG
g_printf("%s::code:%d\n", __FUNCTION__, correct_code);
#endif
  /* Get the clipboard object and copies correct_code in clipboard */
  snprintf(buf, 128, "%06d", correct_code);
  clipboard = gtk_clipboard_get (GDK_SELECTION_CLIPBOARD);
  gtk_clipboard_set_text (clipboard, buf, -1);

}

static void
activate (GtkApplication *app,
          gpointer        user_data)
{
  GtkWidget *window;
  GtkWidget *button;
  GtkWidget *grid;
  //GtkWidget *label;
  GtkWidget *menu_item_Options;
  GtkWidget *menu_Options;
  GtkWidget *submenu_Options;
  GtkWidget *menu_item_Tools;
  GtkWidget *menu_bar;
  GtkClipboard *clipboard;
  GtkWidget *toolbar;
  GtkToolItem *tool_item_add;
  GtkWidget *icon_add;
  GtkWidget *icon_remove;
  GtkToolItem *tool_item_remove;
  GtkWidget *icon_copy;
  GtkToolItem *tool_item_copy;
  GtkWidget *status_bar;

  //static GtkWidget *mydata[4];

  window = gtk_application_window_new (app);
  gtk_window_set_title (GTK_WINDOW (window), "gauthenticator 0.1");
  gtk_window_set_default_size (GTK_WINDOW (window), 500, 0);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_container_set_border_width (GTK_CONTAINER (window), 5);


  //*************************************************************************************
  // Add grid container
  //*************************************************************************************
  grid = gtk_grid_new();
  gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
  gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
  gtk_container_add (GTK_CONTAINER (window), grid);
  gtk_widget_show (grid);
  //*************************************************************************************

  //*************************************************************************************
  // Add menu_bar
  //*************************************************************************************
  menu_bar = gtk_menu_bar_new();
  menu_item_Options = gtk_menu_item_new_with_mnemonic("_Options");
  gtk_menu_shell_append (GTK_MENU_SHELL (menu_bar), menu_item_Options);

  menu_Options = gtk_menu_new();
  submenu_Options = gtk_menu_item_new_with_mnemonic("_New account");
  gtk_menu_shell_append(GTK_MENU_SHELL (menu_Options), submenu_Options);
  gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item_Options), menu_Options);
  gtk_widget_show (menu_item_Options);

  menu_item_Tools = gtk_menu_item_new_with_mnemonic ("_Tools");
  gtk_menu_shell_append (GTK_MENU_SHELL (menu_bar), menu_item_Tools);
  gtk_widget_show (menu_item_Tools);

  gtk_grid_attach(GTK_GRID(grid), menu_bar, 0, 0, 3, 1);
  //*************************************************************************************

  //*************************************************************************************
  // Add toolbar
  //*************************************************************************************
  toolbar = gtk_toolbar_new();
  gtk_widget_show (toolbar);
  icon_copy = gtk_image_new_from_icon_name("edit-copy", GTK_ICON_SIZE_BUTTON);
  tool_item_copy = gtk_tool_button_new(icon_copy, "icon-copy");
  gtk_toolbar_insert(GTK_TOOLBAR(toolbar), tool_item_copy, 0);

  icon_remove = gtk_image_new_from_icon_name("list-remove", GTK_ICON_SIZE_BUTTON);
  tool_item_remove = gtk_tool_button_new(icon_remove, "icon-remove");
  gtk_toolbar_insert(GTK_TOOLBAR(toolbar), tool_item_remove, 0);

  icon_add = gtk_image_new_from_icon_name("list-add", GTK_ICON_SIZE_BUTTON);
  tool_item_add = gtk_tool_button_new(icon_add, "icon-add");
  gtk_toolbar_insert(GTK_TOOLBAR(toolbar), tool_item_add, 0);

  gtk_grid_attach(GTK_GRID(grid), toolbar, 0, 1, 3, 1);
  //*************************************************************************************

  //*************************************************************************************
  // Add status bar
  //*************************************************************************************
  status_bar = gtk_statusbar_new();
  gtk_grid_attach_next_to(GTK_GRID(grid), status_bar, NULL, GTK_POS_BOTTOM, 3, 1);
  gtk_statusbar_push(GTK_STATUSBAR(status_bar), 1, "Ready");
  //*************************************************************************************

  //label = gtk_label_new ("Press the button to calculate token...");
  //gtk_grid_attach(GTK_GRID(grid), label, 0, 2, 3, 1);

  mydata2[0].window = window;
  mydata2[0].grid = grid;
  //mydata[mydata_index].label = label;
  mydata2[0].status_bar = status_bar;

  g_signal_connect (submenu_Options, "activate", G_CALLBACK(new_account), &mydata2);
  g_signal_connect (tool_item_copy, "clicked", G_CALLBACK(clipboard_clicked), &mydata2);
  g_signal_connect (tool_item_add, "clicked", G_CALLBACK(new_account), &mydata2);

  clipboard = gtk_clipboard_get (GDK_SELECTION_CLIPBOARD);
  gtk_clipboard_set_can_store (clipboard, NULL, 0);

  gtk_widget_show_all (window);
}

int main(int argc, char *argv[]) {
  int step_size = 0;
  char *secret;
  unsigned long counter;
  unsigned long tm;
  int correct_code;
  GtkApplication *app;
  int status;

  app = gtk_application_new ("org.gtk.gauthenticator", G_APPLICATION_FLAGS_NONE);
  g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
  status = g_application_run (G_APPLICATION (app), argc, argv);
  g_object_unref (app);

  return status;
}
