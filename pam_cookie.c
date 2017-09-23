/********************************************************************************
 * pam_cookie Linux PAM Module                                                  *
 *                                                                              *
 * pam_cookie is intented to allow an OTP token to remain valid over a period   *
 * of time instead of just once. For example this allows use of OTP's for       *
 * authenticating against a web or imap server. An optional 'cookie' mode       *
 * extends the validity period every time the OTP is entered.                   *
 * Copyright (C) 2011  John Whitbeck <john@whitbeck.fr>                         *
 *                                                                              *
 * This program is free software: you can redistribute it and/or modify         *
 * it under the terms of the GNU General Public License as published by         *
 * the Free Software Foundation, either version 3 of the License, or            *
 * (at your option) any later version.                                          *
 *                                                                              *
 * This program is distributed in the hope that it will be useful,              *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of               *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
 * GNU General Public License for more details.                                 *
 *                                                                              *
 * You should have received a copy of the GNU General Public License            *
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.        *
 ********************************************************************************/


#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <openssl/evp.h>
#include <sys/stat.h>

#define CDB_PATH "/var/cache/pam_cookies"
#define DEFAULT_INTERVAL 600 // 10 minutes
#define PATH_SIZE 250
#define SALT_SIZE 24
#define HASH_SIZE 128
#define CDB_IN_FMT "%24s %128s %lu %lu"
#define CDB_OUT_FMT "%s\t%s\t%lu\t%lu\n"
#define INVALID_TIME 0

/* --- user cookie functions --- */

typedef struct _uc {
  char *salt;
  char *hash;
  time_t touch_time;
  time_t max_time;
} UC;

UC *
uc_new() {
  UC *uc = malloc(sizeof(UC));
  uc->salt = malloc(sizeof(char) * (SALT_SIZE + 1));
  uc->hash = malloc(sizeof(char) * (HASH_SIZE + 1));
  uc->touch_time = INVALID_TIME;
  uc->max_time = INVALID_TIME;
  return uc;
}

void
uc_free(UC *uc) {
  free(uc->salt);
  free(uc->hash);
  free(uc);
}

UC *
uc_open(const char *username) {
  char path[PATH_SIZE];
  UC *uc;
  FILE *f;
  int retval;

  snprintf(path, PATH_SIZE, "%s/%s", CDB_PATH, username);
  f = fopen(path, "r");
  if (f != NULL) {
    uc = uc_new();
    retval = fscanf(f, CDB_IN_FMT, uc->salt, uc->hash, &(uc->touch_time), &(uc->max_time));
    fclose(f);
    if (retval == 4)
      return uc;
    uc_free(uc);
    return NULL;
  }
  return NULL;
}

void
uc_save(UC *uc, const char *username) {
  char tmp_path[PATH_SIZE];
  char path[PATH_SIZE];
  FILE *f;

  umask(007);
  snprintf(tmp_path, PATH_SIZE, "%s/%s.tmp", CDB_PATH, username);
  f = fopen(tmp_path, "w");
  fprintf(f, CDB_OUT_FMT, uc->salt, uc->hash, uc->touch_time, uc->max_time);
  fclose(f);

  snprintf(path, PATH_SIZE, "%s/%s", CDB_PATH, username);
  rename(tmp_path, path);

}

void
uc_remove(const char *username) {
  char path[PATH_SIZE];
  snprintf(path, PATH_SIZE, "%s/%s", CDB_PATH, username);
  remove(path);
}

void
uc_set_max_time(UC *uc, time_t lifetime) {
  uc->max_time = uc->touch_time + lifetime;
}

void
uc_new_salt(UC *uc) {
  int i;
  for (i = 0; i < SALT_SIZE / 8; ++i) {
    snprintf(&(uc->salt[8 * i]), 9, "%08x", rand());
  }
  uc->salt[SALT_SIZE] = '\0';
}

char *
uc_get_hash_string(UC *uc, const char *password) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha512();
  unsigned char md_value[HASH_SIZE * 2];
  unsigned int md_len;
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, uc->salt, strlen(uc->salt));
  EVP_DigestUpdate(mdctx, password, strlen(password));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);

  char *hash_string = malloc(sizeof(char) * (HASH_SIZE + 1)); // 128 hex digits for a 512 bit sha2 hash + trailing '\0'
  int i;
  int *k = (int *) md_value;
  for (i = 0; i < HASH_SIZE / 8; ++i) {
    snprintf(&(hash_string[8 * i]), 9, "%08x", k[i]);
  }

  return hash_string;
}

void
uc_touch(UC *uc) {
  time(&uc->touch_time);
}

void
uc_set_password(UC *uc, const char *password) {
  uc_new_salt(uc);
  if (uc->hash != NULL)
    free(uc->hash);
  uc->hash = uc_get_hash_string(uc, password);
  uc_touch(uc);
}

int
uc_check_password(UC *uc, const char *password) {
  char *new_hash = uc_get_hash_string(uc, password);
  int retval = strncmp(uc->hash, new_hash, 40);
  free(new_hash);
  if (retval == 0)
    return 1;
  return 0;
}

int
uc_not_expired(UC *uc, time_t interval) {
  time_t cur_time;
  time(&cur_time);
  if (uc->max_time != INVALID_TIME && cur_time > uc->max_time)
    return 0;
  if (cur_time > uc->touch_time + interval)
    return 0;
  return 1;
}

/* --- authentication management functions --- */

int
password_prompt(pam_handle_t *pamh, char **password) {
  int retval;
  size_t l;
  struct pam_message *msg, *pmsg[1];
  struct pam_response *resp;
  struct pam_conv *conv;

  /* start pam conversation */
  retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
  if (retval != PAM_SUCCESS)
    return retval;

  /* retrieve password from user */
  msg = malloc(sizeof(struct pam_message));
  pmsg[0] = msg;
  msg->msg = "Enter password: ";
  msg->msg_style = PAM_PROMPT_ECHO_OFF;
  retval = conv->conv(1, (const struct pam_message **) pmsg, &resp, conv->appdata_ptr);
  free(msg);
  if (retval != PAM_SUCCESS)
    return retval;
  if (!resp)
    return PAM_CONV_ERR;

  l = strlen(resp->resp);
  *password = malloc(sizeof(char) * (l + 1));
  strncpy(*password, resp->resp, l + 1);
  (*password)[l] = '\0';

  /* set password for following modules */
  retval = pam_set_item(pamh, PAM_AUTHTOK, resp->resp);
  if (resp)
    free(resp);

  return PAM_SUCCESS;
}

int
fetch_password(pam_handle_t *pamh, char **password) {
  int retval;
  size_t l;
  char *buffer;
  retval = pam_get_item(pamh, PAM_AUTHTOK, (void *) &buffer);
  if (retval != PAM_SUCCESS)
    return retval;

  l = strlen(buffer);
  *password = malloc(sizeof(char) * (l + 1));
  strncpy(*password, buffer, l + 1);
  (*password)[l] = '\0';

  return PAM_SUCCESS;

}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv) {
  int retval = 0;
  int debug = 0;
  int use_first_pass = 0;
  int try_first_pass = 0;
  int is_auth_action = 0;
  int is_touch_action = 0;
  int cookie = 0;
  time_t interval = DEFAULT_INTERVAL;
  time_t lifetime = 0;
  const char *user = NULL;
  char *password = NULL;
  UC *uc = NULL;

  /* Parse options */
  int i;
  for (i = 0; i < argc; ++i) {
    if (strncmp(argv[i], "auth", strlen("auth")) == 0) {
      is_auth_action = 1;
    } else if (strncmp(argv[i], "touch", strlen("touch")) == 0) {
      is_touch_action = 1;
    } else if (strncmp(argv[i], "use_first_pass", strlen("use_first_pass")) == 0) {
      use_first_pass = 1;
    } else if (strncmp(argv[i], "try_first_pass", strlen("try_first_pass")) == 0) {
      try_first_pass = 1;
    } else if (strncmp(argv[i], "cookie", strlen("cookie")) == 0) {
      cookie = 1;
    } else if (strncmp(argv[i], "interval=", strlen("interval=")) == 0) {
      char *interval_ptr = strchr(argv[i], '=');
      interval_ptr++;
      interval = (time_t) atol(interval_ptr) * 60; // convert minutes to seconds
    } else if (strncmp(argv[i], "lifetime=", strlen("lifetime=")) == 0) {
      char *lifetime_ptr = strchr(argv[i], '=');
      lifetime_ptr++;
      lifetime = (time_t) atol(lifetime_ptr) * 60; // convert minutes to seconds
    } else if (strncmp(argv[i], "debug", strlen("debug")) == 0) {
      debug = 1;
    } else {
      pam_syslog(pamh, LOG_AUTHPRIV | LOG_ERR, "unknown option '%s'.", argv[i]);
    }
  }

  if (debug)
    pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "checking options sanity");

  /* sanity checks on options */
  if (is_auth_action && is_touch_action) {
    pam_syslog(pamh, LOG_AUTHPRIV | LOG_ERR, "cannot use both 'auth' and 'touch' options at the same time.");
    return PAM_AUTH_ERR;
  }
  if (!is_auth_action && !is_touch_action) {
    pam_syslog(pamh, LOG_AUTHPRIV | LOG_ERR, "either 'auth' or 'touch' option is required.");
    return PAM_AUTH_ERR;
  }

  /* get user name */
  if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
    return retval;
  }
  if (debug)
    pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "user %s", user);

  /* seed random number generator */
  srand(time(NULL));


  /***************
   * auth action *
   **************/
  if (is_auth_action) {
    if (debug)
      pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "starting auth action.");
    /* get password */
    if (try_first_pass || use_first_pass) {
      if (debug)
        pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "attempting to read password.");
      retval = fetch_password(pamh, &password);
      if (retval != PAM_SUCCESS) {
        if (debug)
          pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "failed to retrieve password.");
        if (use_first_pass) {
          return PAM_AUTHINFO_UNAVAIL;
        } else if (try_first_pass) {
          if ((retval = password_prompt(pamh, &password)) != PAM_SUCCESS)
            return retval;
        }
      }
    } else {
      if ((retval = password_prompt(pamh, &password)) != PAM_SUCCESS)
        return retval;
    }
    /* if we get this far, then we have a valid password */
    if (debug)
      pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "using password '%s'.", password);
    uc = uc_open(user);
    if (uc == NULL) {
      if (debug)
        pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "could not find user '%s' in cookie db.", user);
      free(password);
      return PAM_AUTH_ERR;
    }
    if (!uc_not_expired(uc, interval)) {
      uc_remove(user);
      if (debug)
        pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "cookie for user '%s' has expired.", user);
      free(password);
      uc_free(uc);
      return PAM_AUTH_ERR;
    }
    if (!uc_check_password(uc, password)) {
      if (debug)
        pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "incorrect password for user '%s'.", user);
      uc_free(uc);
      free(password);
      return PAM_AUTH_ERR;
    }
    free(password);
    uc_free(uc);
    return PAM_SUCCESS;
  }


    /****************
     * touch action *
     ****************/
  else {
    if (debug)
      pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "starting touch action.");
    /* get password */
    retval = fetch_password(pamh, &password);
    if (retval != PAM_SUCCESS) {
      if (debug)
        pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "failed to retrieve password.");
      return retval;
    }
    /* if we get this far, then we have a valid password */
    if (debug)
      pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "using password '%s'.", password);
    uc = uc_open(user);
    if (uc == NULL) {
      if (debug)
        pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "creating cookie for user '%s'.", user);
      uc = uc_new();
      uc_set_password(uc, password);
      if (lifetime > 0)
        uc_set_max_time(uc, lifetime);
      uc_save(uc, user);
    } else {
      if (uc_check_password(uc, password)) { // we are still using the same password
        if (cookie) {
          if (debug)
            pam_syslog(pamh, LOG_AUTHPRIV | LOG_DEBUG, "touching cookie for user '%s'.", user);
          uc_touch(uc);
        }
      } else { // this is new password, so we have to reset the lifetime
        uc_set_password(uc, password);
        if (lifetime > 0)
          uc_set_max_time(uc, lifetime);
      }
      uc_save(uc, user);
    }
    uc_free(uc);
    return PAM_SUCCESS;
  }
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
               int argc, const char **argv) {
  return PAM_CRED_ERR;
}

/* --- account management functions --- */

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                 int argc, const char **argv) {
  return PAM_AUTH_ERR;
}

/* --- password management --- */

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                 int argc, const char **argv) {
  return PAM_AUTHTOK_ERR;
}

/* --- session management --- */

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char **argv) {
  return PAM_SESSION_ERR;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                     int argc, const char **argv) {
  return PAM_SESSION_ERR;
}

/* end of module definition */

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_deny_modstruct = {
    "pam_cookie",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};
#endif
