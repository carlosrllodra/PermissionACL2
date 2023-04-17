<?php

/**
 * PermissionACL2 extension - implements namespace/category/page
 * access control to users/groups with ACLs.
 *
 * Based on PermissionACL by Jan Vavříček:
 * https://mediawiki.org/wiki/Extension:PermissionACL
 * and adapted to modern MediaWiki by Carlos Rodriguez.
 *
 * Copyright (C) 2023  Carlos Rodriguez Llodrá
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * @file Hooks.php
 * @ingroup Extensions
 * @author Carlos Rodriguez Llodrá <https://github.com/carlosrllodra>
 * @license GPL-2.0-or-later
 */

namespace MediaWiki\Extension\PermissionACL2;



if( !defined( 'MEDIAWIKI' ) ) {
    echo("This file is an extension to the MediaWiki software and cannot be used standalone.\n");
    die(1);
}



//use Article;
use MediaWiki;
use MediaWiki\Permissions\Hook\GetUserPermissionsErrorsHook;
use MediaWiki\User\UserGroupManager;
use Language;
use PermissionsError;
use Title;
use User;
use UserGroupMembership;



/**
 * Holds the hooks for the Lockdown extension.
 */
class Hooks implements GetUserPermissionsErrorsHook
{
	/**
	 * @var UserGroupManager
	 */
	private $userGroupManager;
	private $contentLang;



	/**
	 * @param UserGroupManager $userGroupManager
	 */
	public function __construct( UserGroupManager $userGroupManager, Language $contentLang ) {
		$this->userGroupManager = $userGroupManager;
		$this->contentLang = $contentLang;
	}

	/**
	 * Fetch an appropriate permission error (or none!)
	 *
	 * @param Title $title being checked
	 * @param User $user whose access is being checked
	 * @param string $action being checked
	 * @param array|string|MessageSpecifier &$result User
	 *   permissions error to add. If none, return true. $result can be
	 *   returned as a single error message key (string), or an array of
	 *   error message keys when multiple messages are needed
	 * @return bool
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors
	 */
	public function onGetUserPermissionsErrors( $title, $user, $action, &$result ) {
		global $wgPermissionACL, $wgPermissionACL_Superuser, $wgWhitelistRead;

		$result = null;

		//if not set - grant access
		if(!isset($wgPermissionACL)) {
			return true;
		}
		// don't impose extra restrictions on UI pages
		if ( $title->isUserConfigPage() ) {
			return true;
		}
		if ( $action == 'read' && is_array( $wgWhitelistRead ) ) {
			// don't impose read restrictions on whitelisted pages
			if ( in_array( $title->getPrefixedText(), $wgWhitelistRead ) ) {
				return true;
			}
		}
		if(isset($wgPermissionACL_Superuser)) {
			//Superuser can do everything - no need to read ACLs
			if(is_array($wgPermissionACL_Superuser)) {
				if(in_array(strtolower($user->getName()), $this->ArrayToLower($wgPermissionACL_Superuser)))
					return true;
			} else if(strtolower($user->getName()) == strtolower($wgPermissionACL_Superuser)) {
				return true;
			}
		}

		foreach ($wgPermissionACL as $rule) {
			//process ACLs
			if (!$this->isRuleValid ($rule)) //syntax checking
				continue;

			if ($this->isRuleApplicable ($rule, $title, $user, $action)) {
				if($this->isAllowed ($rule)) {
					return true;
				} else {
					$result = [ wfMessage ('permissionacl2-denied')->parse() ];
					return false;
				}
			}
		}

		// If the user's trying to "read"/"edit" a page which doesn't exist; 
		// check for "create" and "createpage" actions
		if (!$title->isKnown() && (($action == 'read') || ($action == 'edit'))) {
			return $this->onGetUserPermissionsErrors ($title, $user, 'create', $result) ||
			       $this->onGetUserPermissionsErrors ($title, $user, 'createpage', $result);
		}

		//implicit end rule - DENY ALL
		$result = [ wfMessage ('permissionacl2-denied')->parse() ];
		return false;
	}


	private function isRuleValid($rule) {
		/* rule parts:
		   'group' || 'user'
		   'namespace' || 'page' || 'category'
		   'action' = (read, edit, create, move, *)
		   'operation' = (permit, allow, deny)
		*/
		$tmp_actions    = array('read', 'edit', 'create', 'move', '*');
		$tmp_operations = array('permit', 'allow', 'deny');

		if ((isset($rule['group']) ^ isset($rule['user'])) && (isset($rule['namespace']) ^ isset($rule['page']) ^ isset($rule['category']))) {
			if (isset($rule['action']) && ((is_string($rule['action']) && in_array($rule['action'], $tmp_actions)) || is_array($rule['action']))) {
				if (isset($rule['operation']) && in_array($rule['operation'], $tmp_operations)) {
					return true;
				}
			}
		}

		return false;
	}


	private function isRuleApplicable($rule, $title, $user, $action) {
	    //group|user rule
	    if(isset($rule['group'])) { //group rule
		if(is_array($rule['group']))
		    $tmp = $this->ArrayToLower($rule['group']);
		else
		    $tmp = strtolower($rule['group']);

		$groups = $this->ArrayToLower($this->userGroupManager->getUserEffectiveGroups ($user));
		if(!( (is_string($tmp) && in_array($tmp, $groups)) ||
		      (is_array($tmp) && count(array_intersect($tmp, $groups))>0)
		    )) return false;
	    }
	    else { // user rule
		if(is_array($rule['user']))
		    $tmp = $this->ArrayToLower($rule['user']);
		else
		    $tmp = strtolower($rule['user']);
		$tmp2 = strtolower($user->getName());

		if(!( (is_string($tmp) && $tmp=='*') ||
		      (is_string($tmp) && $tmp==$tmp2) ||
		      (is_array($tmp) && in_array($tmp2, $tmp))
		    )) return false;
	    }

	    //namespace|page|category rule
	    if(isset($rule['namespace'])) { //namespace rule
		$tmp = $rule['namespace'];
		$tmp2 = $title->getNamespace();

		if(!( (is_int($tmp) &&  $tmp==$tmp2) ||
		      (is_string($tmp) && $tmp=='*') ||
		      (is_array($tmp) && in_array($tmp2, $tmp))
		    )) return false;
	    }
	    else if(isset($rule['page'])){ //page rule
		$tmp = $rule['page'];
		$tmp2 = $title->getPrefixedText();

		if(!( (is_string($tmp) && $tmp==$tmp2) ||
		      (is_string($tmp) && $tmp=='*') ||
		      (is_array($tmp) && in_array($tmp2, $tmp))
		    )) return false;
	    }
	    else { //category rule
		$tmp = $rule['category'];
		$tmp2 = $title->getParentCategories();
		$categs = array();

		if(is_array($tmp2)) {
		    $tmp_pos = strrpos($this->contentLang->getNSText(NS_CATEGORY), ':');

		    foreach($tmp2 as $cat => $page) {
			if($tmp_pos === false) {
			    $categs[] = substr($cat, strpos($cat, ':')+1);
			}
			else {
			    $tmp_categ = substr($cat, $tmp_pos+1);
			    $categs[] = substr($tmp_categ, strpos($tmp_categ, ':')+1);
			}
		    }
		}

		if(!( (is_string($tmp) && is_array($tmp2) && in_array($tmp, $categs)) ||
		      (is_string($tmp) && $tmp=='*') ||
		      (is_array($tmp)  && is_array($tmp2) && count(array_intersect($tmp, $categs))>0)
		    )) return false;
	    }

	    //action rule
	    if(is_array($rule['action']))
		$tmp = $this->ArrayToLower($rule['action']);
	    else
		$tmp = strtolower($rule['action']);

	    return ($tmp == $action) ||
		  (is_string($tmp) && $tmp=='*') ||
		  (is_array($tmp) && in_array($action, $tmp));
	}


	private function isAllowed($rule) {
		$op = strtolower($rule['operation']);
		return ($op == 'permit') || ($op == 'allow');
	}


	private function ArrayToLower($ar) {
		$tmp = array();
		foreach ($ar as $index => $value)
			$tmp[$index] = strtolower($value);
		return $tmp;
	}
}

?>