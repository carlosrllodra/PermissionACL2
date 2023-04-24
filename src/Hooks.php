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



if (!defined ('MEDIAWIKI')) {
    echo ("This file is an extension to the MediaWiki software and cannot be used standalone.\n");
    die (1);
}



use MediaWiki;
use MediaWiki\Permissions\Hook\GetUserPermissionsErrorsHook;
use MediaWiki\User\UserGroupManager;
use Language;
use PermissionsError;
use Title;
use User;
use UserGroupMembership;



/**
 * Holds the hooks for the PermissionACL2 extension.
 */
class Hooks implements GetUserPermissionsErrorsHook
{
	private $userGroupManager;	// The user group manager.
	private $contentLang;		// The content language object.



	/**
	 * Constructor.
	 */
	public function __construct (UserGroupManager $userGroupManager, Language $contentLang)
	{
		$this->userGroupManager = $userGroupManager;
		$this->contentLang = $contentLang;
	}



	/**
	 * Check permission and set an appropriate error (or none!)
	 *
	 * @param[in] Title $title The title (page) being checked.
	 * @param[in] User $user User whose access is being checked.
	 * @param[in] string $action User action being checked.
	 * @param[out] array|string|MessageSpecifier &$result User permission
	 *    error(s) to add. If none, return true. $result can be returned
	 *    as a single error message key (string), or an array of error
	 *    message keys when multiple messages are needed.
	 * @return Returns true if $user is allowed to perform $action on $title.
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors
	 */
	public function onGetUserPermissionsErrors ($title, $user, $action, &$result)
	{
		global $wgPermissionACL, $wgPermissionACL_Superuser, $wgWhitelistRead;

		$result = null;

		// If $wgPermissionACL is not set, grant access.
		if (!isset ($wgPermissionACL))
			return true;
		// Don't impose extra restrictions on user configuration pages.
		if ($title->isUserConfigPage ())
			return true;
		// Don't impose *read* restrictions on whitelisted pages.
		if (($action == 'read') && is_array ($wgWhitelistRead) &&
		    in_array ($title->getPrefixedText (), $wgWhitelistRead))
			return true;

		// Superuser can do anything - no need to read ACLs.
		if (isset ($wgPermissionACL_Superuser)) {
			if (is_array ($wgPermissionACL_Superuser)) {
				if (in_array (strtolower ($user->getName ()), $this->ArrayToLower ($wgPermissionACL_Superuser)))
					return true;
			} else if (strtolower ($user->getName ()) == strtolower ($wgPermissionACL_Superuser)) {
				return true;
			}
		}

		// Process ACLs until one of them matches.
		foreach ($wgPermissionACL as $rule) {
			if (!$this->isRuleValid ($rule)) {
				$msg = print_r ($rule, true);
				die ("<pre>Invalid rule:\n$msg\n</pre>");
			}
			if ($this->isRuleApplicable ($rule, $title, $user, $action)) {
				$allowed = $this->isAllowed ($rule);
				if (!$allowed)
					$result[] = wfMessage ('permissionacl2-denied')->parse ();
				return $allowed;
			}
		}

		// If the user is trying to "read"/"edit" a page which doesn't exist,
		// check for "create" and "createpage" actions instead.
		if (!$title->isKnown () && (($action == 'read') || ($action == 'edit'))) {
			return $this->onGetUserPermissionsErrors ($title, $user, 'create', $result) ||
			       $this->onGetUserPermissionsErrors ($title, $user, 'createpage', $result);
		}

		// Implicit last rule: DENY ALL.
		$result[] = wfMessage ('permissionacl2-denied')->parse ();
		return false;
	}


	/**
	 * Check rule syntax (single rule).
	 *
	 * @param[in] array $rule The rule to check.
	 * @return Returns true if the rule seems valid.
	 */
	private function isRuleValid ($rule)
	{
		/* rule parts:
		   'group' || 'user'  =>  string || array
		   'namespace' || 'page' || 'category'  =>  string || array
		   'action'  =>  ('read', 'edit', 'create', 'createpage', 'move', '*')
		   'operation'  =>  ('permit', 'allow', 'deny')
		   'mode'  =>  ('simple', 'pcre', <or not set>)
		*/
		$tmp_modes      = array ('simple', 'pcre');
		$tmp_actions    = array ('read', 'edit', 'create', 'createpage', 'move', '*');
		$tmp_operations = array ('permit', 'allow', 'deny');

		return (isset ($rule ['group']) ^ isset ($rule ['user'])) &&
		       (isset ($rule ['namespace']) ^ isset ($rule ['page']) ^ isset ($rule ['category'])) &&
		       isset ($rule ['action']) &&
		       ((is_string ($rule ['action']) && in_array (strtolower ($rule ['action']), $tmp_actions)) || is_array ($rule['action'])) &&
		       (isset ($rule ['operation']) && in_array (strtolower ($rule ['operation']), $tmp_operations)) &&
		       (!isset ($rule ['mode']) || (isset ($rule ['mode']) && in_array (strtolower ($rule ['mode']), $tmp_modes)));
	}



	/**
	 * Check if a rule is applicable to specified title, user and action.
	 *
	 * @param[in] array $rule The rule being checked.
	 * @param[in] Title $title The title (page) to check against.
	 * @param[in] User $user User to check against.
	 * @param[in] string $action User action to check against.
	 * @return Returns true if $rule can be applied to given $title/$user/$action tuple.
	 */
	private function isRuleApplicable ($rule, $title, $user, $action)
	{
		// Group or user.
		if (isset ($rule ['group'])) {
			if (is_array ($rule ['group']))
				$tmp = $this->ArrayToLower ($rule ['group']);
			else
				$tmp = strtolower ($rule ['group']);

			$groups = $this->ArrayToLower ($this->userGroupManager->getUserEffectiveGroups ($user));
			if (!((is_string ($tmp) && in_array ($tmp, $groups)) ||
			      (is_array ($tmp) && (count (array_intersect ($tmp, $groups)) > 0))))
				return false;

		} else /*if (isset ($rule ['user']))*/ {
			if (is_array ($rule ['user']))
				$tmp = $this->ArrayToLower ($rule ['user']);
			else
				$tmp = strtolower ($rule ['user']);
			$tmp2 = strtolower ($user->getName ());

			if (!((is_string ($tmp) && ($tmp == '*')) ||
			      (is_string ($tmp) && ($tmp == $tmp2)) ||
			      (is_array ($tmp) && in_array ($tmp2, $tmp))))
				return false;
		}

		// Action.
		if (is_array ($rule ['action']))
			$tmp = $this->ArrayToLower ($rule ['action']);
		else
			$tmp = strtolower ($rule ['action']);

		if (!((is_string ($tmp) && (($tmp == $action) || ($tmp == '*'))) ||
		      (is_array ($tmp) && in_array ($action, $tmp))))
			return false;

		// Target (namespace, page or category).
		if (isset ($rule ['mode']) && (strcasecmp ($rule ['mode'], 'pcre') == 0))
			return $this->isRuleApplicable_PcreTarget ($rule, $title);
		//else
		return $this->isRuleApplicable_SimpleTarget ($rule, $title);
	}



	/**
	 * Check if a rule is applicable to specified title.
	 *
	 * This is the "simple mode" check, as it was done in PermissionACL extension.
	 *
	 * @param[in] array $rule The rule being checked.
	 * @param[in] Title $title The title (page) to check against.
	 * @return Returns true if $rule can be applied to given $title tuple.
	 */
	private function isRuleApplicable_SimpleTarget ($rule, $title)
	{
		// Namespace, page or category.
		if (isset ($rule ['namespace'])) {
			$tmp = $rule ['namespace'];
			$tmp2 = $title->getNamespace ();

			if (!((is_int ($tmp) && ($tmp == $tmp2)) ||
			      (is_string ($tmp) && ($tmp == '*')) ||
			      (is_array ($tmp) && in_array ($tmp2, $tmp))))
				return false;

		} else if (isset ($rule ['page'])) {
			$tmp = $rule ['page'];
			$tmp2 = $title->getPrefixedText ();

			if (!((is_string ($tmp) && $tmp == $tmp2) ||
			      (is_string ($tmp) && $tmp == '*') ||
			      (is_array ($tmp) && in_array ($tmp2, $tmp))))
				return false;

		} else if (isset ($rule ['category'])) {
			$tmp = $rule ['category'];
			$tmp2 = $title->getParentCategories ();
			$categs = array ();

			if (is_array ($tmp2)) {
				$tmp_pos = strrpos ($this->contentLang->getNsText (NS_CATEGORY), ':');

				foreach ($tmp2 as $cat => $page) {
					if ($tmp_pos === false) {
						$categs[] = substr ($cat, strpos ($cat, ':') + 1);
					} else {
						$tmp_categ = substr ($cat, $tmp_pos + 1);
						$categs[] = substr ($tmp_categ, strpos ($tmp_categ, ':') + 1);
					}
				}
			}

			if (!((is_string ($tmp) && is_array ($tmp2) && in_array ($tmp, $categs)) ||
			      (is_string ($tmp) && ($tmp == '*')) ||
			      (is_array ($tmp) && is_array ($tmp2) && (count (array_intersect ($tmp, $categs)) > 0))))
				return false;

		} else {
			// Unreachable (if rule is valid).
			return false;
		}
		return true;  
	}



	/**
	 * Check if a rule is applicable to specified title.
	 *
	 * This is the "PCRE mode" check, using regular expressions instead of simple string comparisons.
	 *
	 * @param[in] array $rule The rule being checked.
	 * @param[in] Title $title The title (page) to check against.
	 * @return Returns true if $rule can be applied to given $title tuple.
	 */
	private function isRuleApplicable_PcreTarget ($rule, $title)
	{
		// Namespace, page or category.
		if (isset ($rule ['namespace'])) {
			if (!$this->regexAnyMatch ($rule ['namespace'], $title->getNamespace ()))
				return false;

		} else if (isset ($rule ['page'])) {
			if (!$this->regexAnyMatch ($rule ['page'], $title->getPrefixedText ()))
				return false;

		} else if (isset ($rule ['category'])) {
			$categories = array ();
			$tmp = $title->getParentCategories ();
			if (is_array ($tmp)) {
				/* Not sure what Jan was doing here... remove prefix (if present)
				   from NS_CATENGORY namespace name and then remove that namespace
				   name from category name? */
				$tmp_pos = strrpos ($this->contentLang->getNsText (NS_CATEGORY), ':');
				foreach ($tmp as $cat => $page) {
					if ($tmp_pos === false) {
						$categories[] = substr ($cat, strpos ($cat, ':') + 1);
					} else {
						$tmp_categ = substr ($cat, $tmp_pos + 1);
						$categories[] = substr ($tmp_categ, strpos ($tmp_categ, ':') + 1);
					}
				}
			}
			if (!$this->regexAnyMatch ($rule ['category'], $categories))
				return false;

		} else {
			// Unreachable (if rule is valid).
			return false;
		}
		return true;  
	}



	/**
	 * Check if given subject(s) match any of given regular expression(s).
	 *
	 * @param[in] string|array $in_regex Either a single regex or an array of
	 *    regular expressions.
	 * @param[in] string|array $in_subject Either a single string or an array
	 *    of strings to match $in_regex against.
	 * @return Returns true if at least one of the regular expressions matches
	 *    at least one of the subjects; returns false if *none* of them match.
	 */
	private function regexAnyMatch ($in_regex, $in_subject)
	{
		if (is_array ($in_regex))
			$in_regex_array = $in_regex;
		else
			$in_regex_array = array ($in_regex);

		if (is_array ($in_subject))
			$in_subject_array = $in_subject;
		else
			$in_subject_array = array ($in_subject);

		foreach ($in_regex_array as $regex) {
			foreach ($in_subject_array as $subject) {
				$result = preg_match ($regex, $subject);
				if ($result === false)
					die ("<pre>Invalid regular expression: '$regex'.\n</pre>");
				else if ($result > 0)
					return true;
			}
		}

		return false;
	}



	/**
	 * Check if given rule's 'operation' is a synonym of 'allow'.
	 */
	private function isAllowed ($rule)
	{
		$op = strtolower ($rule ['operation']);
		return ($op == 'permit') || ($op == 'allow');
	}



	/**
	 * Convert all strings in an array to lowercase.
	 */
	private function ArrayToLower ($ar)
	{
		$tmp = array ();
		foreach ($ar as $index => $value)
			$tmp [$index] = strtolower ($value);
		return $tmp;
	}
}

?>