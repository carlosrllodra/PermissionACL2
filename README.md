# README for the PermissionACL2 extension for MediaWiki

Copyright © 2023 Carlos Rodriguez Llodrá

Licenses:
- GNU General Public Licence (GPL)
- GNU Free Documentation License (GFDL)


The **PermissionACL(2)** extensions implement a way to restrict access to specific
**{namespaces, pages, categories}** based on **user group** or **user name**. This
provides a more fine grained security model than the one provided by the default
*$wgGroupPermissions*.

**PermissionACL(2)** extensions configuration is based on ACL (Access Control
List) - list of rules which are processing from first to last. **First applicable
rule is used! At the end of list is an implicit *DENY TO ALL* rule!**

The **PermissionACL2** extension for MediaWiki is just a migration of **PermissionACL**
by Jan Vavříček (see: <https://www.mediawiki.org/wiki/Extension:PermissionACL>)
to make it compatible with modern MediaWiki versions (tested with MW 1.39, should
work also with MW 1.35 and later).

The same **PermissionACL** configuration syntax is applicable to **PermissionACL2**
with a single addition: *$wgPermissionACL* *'operation'* supports the *'allow'*
value as a synonym of *'permit'*.

Of course, installation procedure is also a little bit different.


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

**Note,** if you don't define *$wgPermissionACL* this extension will do nothing; *on
the other hand if you define it as an empty array then access to (almost) every page
will be denied.*


## Usage

If *$wgPermissionACL* is set, then ACL mode is used; if not, the extension will do nothing.

Rules are array elements and they are applied in the order they are defined.

Syntax of rules (every rule has 4 parts):

1. *Which page:* selection of **pages**, **namespaces** or **categories**.
2. *Which user:* selection of **users** or **groups**.
3. *Which action:* selection of actions ([user permission](https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors)
   actions - **read**, **edit**, **create**, **move**, **...**)
4. *Operation:* **permit** or **deny** access (or **allow**, as a synonym of *permit*).

First, second and third rule parts can be:

- A single value (string).
- An array of values (array of strings).
- An asterisk, meaning ***ALL***.

### Summary of syntax

The following may be repeated multiple times to add rules to the ACL:

``` [php]
$wgPermissionACL[] = array(
	{'group' | 'user'} => {<username> | <groupname> | '*'} [, {<username> | <groupname> | '*'}...] ,
	{'namespace' | 'page' | 'category'} =>  <namespace> [, <namespace>...] ,
	'action'    => {'read', 'edit', 'create', 'move', '*'} [, {'read', 'edit', 'create', 'move', '*'}...] ,
	'operation' => {'permit', 'allow', 'deny'}
);
```

### Example

This is a sample configuration for the following scenario:

- Namespaces: **Private, Ccna, Ccnp, Ns, Fwl**
- User groups: **private, ccna, ccnp, ns, fwl**
- Group **ccna** has RW access only to namespace **Ccna**, group **fwl** to NS **Fwl**, etc...
- Group **private** has RW access to all namespaces.
- Anonymous users (not logged in) can only read **NS_MAIN** namespace.
- Administrators (users "wikisysop" and "vav166") can do anything.

``` [php]
wfLoadExtension ('PermissionACL2');
$wgExtraNamespaces = array( 100 => "Private",
			    101 => "Private_Talk",
			    102 => "Ccna",
			    103 => "Ccna_Talk",
			    104 => "Ccnp",
			    105 => "Ccnp_Talk",
			    106 => "Ns",
			    107 => "Ns_Talk",
			    108 => "Fwl",
			    109 => "Fwl_Talk" );

$wgGroupPermissions['ccna']['read'] = true;
$wgGroupPermissions['ccnp']['read'] = true;
$wgGroupPermissions['ns']['read']   = true;
$wgGroupPermissions['fwl']['read']  = true;
$wgGroupPermissions['private']['read'] = true;

// Page whitelist is used, but same thing can be done by ACL:
/*
$wgPermissionACL[] = array('group'     => '*',
			   'page'      => array('Special:UserLogin', 'Special:UserLogout', 'Special:Resetpass', 'Special:Confirmemail'),
			   'action'    => 'read',
			   'operation' => 'permit');
*/
$wgWhitelistRead = array('Special:Userlogin', 'Special:Userlogout', 'Special:Resetpass', 'Special:Confirmemail');

// wgPermissionACL_Superuser is only simplification - same result as ACL:
/*
$wgPermissionACL[] = array('user'      => array('wikisysop', 'vav166'),
			   'page'      => '*',
			   'action'    => '*',
			   'operation' => 'permit');
*/
$wgPermissionACL_Superuser = array('wikisysop', 'vav166');

$wgPermissionACL[] = array('group'     => '*',
			   'namespace' => NS_MAIN,
			   'action'    => 'read',
			   'operation' => 'permit');

$wgPermissionACL[] = array('group'     => 'user',
			   'namespace' => array(NS_MAIN, NS_SPECIAL, NS_USER, NS_CATEGORY),
			   'action'    => 'read',
			   'operation' => 'permit');

$wgPermissionACL[] = array('group'     => 'private',
			   'namespace' => array(100, 101, 102, 103, 104, 105, 106, 107, 108, 109),
			   'action'    => '*',
			   'operation' => 'permit');

$wgPermissionACL[] = array('group'     => 'ccna',
			   'namespace' => array(102, 103),
			   'action'    => '*',
			   'operation' => 'permit');

$wgPermissionACL[] = array('group'     => 'ccnp',
			   'namespace' => array(104, 105),
			   'action'    => '*',
			   'operation' => 'permit');

$wgPermissionACL[] = array('group'     => 'ns',
			   'namespace' => array(106, 107),
			   'action'    => '*',
			   'operation' => 'permit');

$wgPermissionACL[] = array('group'     => 'fwl',
			   'namespace' => array(108, 109),
			   'action'    => '*',
			   'operation' => 'permit');
```
