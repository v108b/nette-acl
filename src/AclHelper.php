<?php

namespace V108B\Nette\Security;

abstract class AclHelper
{
	const SIGN_IN_ACTION = ':Sign:in';
	const ROOT_ROLE = 'root';
	const ALL = \Nette\Security\Permission::ALL;

	/** @var \Nette\Security\User */
	private $user;

	/** @var \Nette\Security\Permission */
	private $acl;

	public function __construct(\Nette\Security\User $user)
	{
		$this->user = $user;
		$this->acl = new \Nette\Security\Permission();
		$this->config();
	}

	public abstract function config();

	public function addRoles($roles)
	{
		if ($roles !== self::ALL) {
			$roles = is_array($roles) ? $roles : [$roles];

			foreach ($roles as $role) {
				if (!$this->acl->hasRole($role)) {
					$this->acl->addRole($role);
				}
			}
		}
	}

	public function addResources($resources)
	{
		if ($resources !== self::ALL) {
			$resources = is_array($resources) ? $resources : [$resources];

			foreach ($resources as $resource) {
				if (!$this->acl->hasResource($resource)) {
					$this->acl->addResource($resource);
				}
			}
		}
	}

	public function allow($roles = self::ALL, $resources = self::ALL, $privileges = self::ALL, $assertion = NULL)
	{
		$this->addResources($resources);
		$this->addRoles($roles);
		$this->acl->allow($roles, $resources, $privileges, $assertion);
	}

	public function addRole($role)
	{
		$this->acl->addRole($role);
	}

	public function check($resource, $privilege)
	{
		if ($this->user->isInRole(static::ROOT_ROLE)) {
			return true;
		}

		if (!array_reduce($this->user->getRoles(), function ($prev, $role) use ($resource, $privilege) {
			return ($this->acl->hasRole($role) && $this->acl->hasResource($resource) && $this->acl->isAllowed($role, $resource, $privilege)) || $prev;
		}, false)
		) {
			throw new \AclException("Unauthorized access to resource '{$resource}' privilege '{$privilege}' :(", 403);
		}
	}
}
