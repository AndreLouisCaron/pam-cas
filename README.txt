1. Download and compile `pam_python` from the project page.
     <http://ace-host.stuart.id.au/russell/files/pam_python/>

2. Copy files somewhere on server (now refered to as `/path/to/`.

3. "Install" files on the server.
   $ ln -s /lib/security/pam_cas.py /path/to/cas.py
   $ ln -s /etc/pam.d/cas           /path/to/cas

4. Configure `cas` file to select required users.

5. Configure NGINX.  Make sure NGINX PAM support is configured.  Might need
   to build from source to ensure this.  Interesting directives are `auth_pam`
   and `auth_pam_service_name`.  The former is the authentication realm and
   the second must match the name of the PAM service installed in `/etc/pam.d`.
   If following the directives above, it should be called `cas`.

   auth_pam              "CAS @ UdeS";
   auth_pam_service_name "cas";
