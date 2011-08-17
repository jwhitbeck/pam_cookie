
pam_cookie PAM module
--------------------------------

pam_cookie is intented to allow a one-time-password (OTP) token to
remain valid over a period of time instead of just once. For example
this allows use of OTP's for authenticating against a web or imap
server. An optional 'cookie' mode may extend the validity period every
time the correct OTP is entered. It was conceived with pam_mobile_otp
(see motp.sourceforge.net) in mind but it should work with any pam
authentication module (e.g. pam_unix.so). 

Pwauth (http://code.google.com/p/pwauth/) may be used in conjuction
with mod-authn-external (http://code.google.com/p/mod-auth-external/)
to connect the apache web server to PAM.


PLATFORMS
~~~~~~~~~

This module has been developped and tested on the following platforms:
- Ubuntu Linux 11.04 and 10.04

Please let me know if you were able to get it to work on different
platforms.


COMPILATION
~~~~~~~~~~~

Requirements:
- Openssl development headers
- LibPAM development headers

Then simply type 'make'


INSTALLATION
~~~~~~~~~~~~

The only supported pam module is "auth"

For installation you must:

     1. Type 'sudo make install'. This will move pam_cookie.so to
        /lib/security and create the directory /var/cache/pam_cookie

     2. Set the permissions on the /var/cache/pam_cookie directory so
        that the process using the module will have write access to
        it. For example:
	$ sudo chmod 6660 /var/cache/pam_cookie
        $ sudo chown www-data:www-data /var/cache/pam_cookie

     3. Configure the relevant pam config file. This part is a little
        tricky so having a good knowledge of how PAM modules are
        configured and interact work is essential. Make sure you
        understand the example config below. It is very easy to either
        completely brick you system or open it up to the world.

     4. Try to log in!



CONFIGURATION
~~~~~~~~~~~~~

The auth module has two modes: 'auth' and 'touch'. One or the either
must be specified. Here are the pam config options:

   auth 
       
       Set auth mode. Auth mode read the current password and compares it
       to its database to check it is valid and if has not expired.


   touch

       Set touch mode. Touch mode creates new entries in the database
       for passwords that were validated by another module, or updates
       the timestamps of existing passwords.


   use_first_pass
       
       Only use with auth mode. If set, the module does not ask for
       the passcode, but uses the password given earlier to an other
       module.


   try_first_pass

	Only use with auth mode. If set, the module only asks for a
	passcode, if password that was set earlier is not the correct
	passcode.


   interval=<value>

        Only use with auth mode. Value is set in minutes and defaults
        to 10. Let last_t be the password's last timestamp and cur_t
        be the system's current time. If (cur_t > last_t+value), then
        the password has expired and the module rejects it.


   lifetime=<value>

        Only use with touch mode. Value is set in minutes and defaults
        to 0 (ie infinity). Let crea_t be the time when the password
        was entered into the database. Let cur_t be the system's
        current time. If (cur_t > crea_t + value), then the password
        has expired and the module rejects it.


   cookie

       Only use with touch mode. Every time a saved password is
       entered correctly, update it's timestamp to the system's
       current time. If lifetime is unset, then that password could
       conceivably remain valid as long as it keeps getting updated
       every 'interval' minutes.


   debug

       Log debugging information to /var/log/auth.log. Warning: this
       will print passwords in cleartext into your log files.



EXAMPLE PAM CONFIG
~~~~~~~~~~~~~~~~~~

auth	[success=1 default=ignore]	pam_cookie.so auth interval=10
auth	[success=ok default=1]		pam_mobile_otp.so use_first_pass
auth	[default=1]			pam_cookie.so touch cookie lifetime=30
auth	requisite			pam_deny.so
auth	required			pam_permit.so

Line 1: This is the 'auth' mode. Here pam_cookie asks for the user
password an compares it to the ones in its database. If it is
identical and is was last used less than 10minutes ago (interval=10)
and first used less 30mins ago (lifetime=30 on line 3) the module
succeeds. It then skips pam_mobile_otp.so and goes straight to line 3.
If it fails, the auth process goes to line 3.

Line 2: standard pam_mobile_otp.so authentication. If this succeeds,
proceed to line 3, if it fails, it skips line 3 and goes straight to
line 4 (default=1 param).

Line 3: This line always succeeds and then proceeds the line 5. Here
pam_cookie.so is in the 'touch' mode. Two options: (i) if the password
does not exist in the database, then create it and set a 30min
lifetime; or (ii) if the password is already in the databse, since the
'cookie' option was passed, update the password's timestamp with the
current time.

Line 4: fail and return

Line 5: return success



SECURITY CONSIDERATIONS
~~~~~~~~~~~~~~~~~~~~~~~

- Extending the validity period of a one-time password degrades its
  security. Only use where stricly needed (e.g. web server) and not
  where it is useless (e.g. ssh). Make sure you understand the
  'interval' and 'lifetime' options and set them
  accordingly. Furthermore, you should protect your web server against
  brute-force attacks using for example fail2ban.

- Functions are not thread safe.



Any comments, bug reports or questions (to the module only) to
John Whitbeck <john@whitbeck.fr>


LICENSE
~~~~~~~

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

