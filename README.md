# README for the PermissionACL2 extension

Copyright © 2023 Carlos Rodriguez Llodrá

Licenses:
- GNU General Public Licence (GPL)
- GNU Free Documentation License (GFDL)


The PermissionACL2 extension for MediaWiki is just a migration of PermissionACL
by Jan Vavříček (see: https://www.mediawiki.org/wiki/Extension:PermissionACL )
to make it compatible with modern MediaWiki versions (tested with MW 1.39, should
work also with MW 1.35 and later).

The same PermissionACL configuration syntax is applicable to PermissionACL2
with a single addition: $wgPermissionACL 'operation' supports the 'allow' value
as a synonym of 'permit'.

And of course, installation procedure is a little bit different.


## Installation

1. Clone this repository into your MediaWiki's extensions directory:

   ```
   cd .../extensions
   git clone https://github.com/carlosrllodra/PermissionACL2.git
   ```

2. Not mandatory but recommended: deny web access to the extension directory.
    - Eg, if using Apache web server, create the file PermissionACL2/.htaccess
      and add the following line to it:  
      `Require all denied`

3. Add the following code at the bottom of your LocalSettings.php:

   ``` [php]
   wfLoadExtension ('PermissionACL2');
   $wgPermissionACL_Superuser = array (...);  // Array of additional superusers, optional.
   $wgPermissionACL = array (...);  // ACL structure.
   ```

4. Done – Navigate to Special:Version on your wiki to verify that the extension is
   successfully installed.

**Note,** if you don't define $wgPermissionACL this extension will do nothing; *on
the other hand if you define it as an empty array then access to (almost) every page
will be denied.*
