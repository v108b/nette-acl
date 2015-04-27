# nette-acl

## Install
Install package via composer 

extend class \V108B\Nette\Security\AclHelper and implement method config()

```php
class AclHelper extends \V108B\Nette\Security\AclHelper {
	public function config()
	{
		$this->allow('editor','articles','update');
	}
}
```

add to services section in config.neon:

```
- App\AclHelper
```

## Usage

Use wherever you want

```php
class Model {
	private $acl;

	public function __construct(Nette\Database\Context $database, \App\AclHelper $acl)
	{
		$this->database = $database;
		$this->acl = $acl;
	}

	public function updateArticle($id, $values)
	{
		$this->acl->check("articles", 'update');
		return $this->database->articles->get($id)->update($values);
	}
}
```